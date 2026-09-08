use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use crate::crypto::MasterKey;
use crate::error::ShadowError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub session_id: String,
    pub role: String,
    pub content: String,
    pub finish_reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: String,
    pub user_id: String,
    pub title: String,
    pub model_id: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct SessionStore<'a> {
    conn: &'a Connection,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl<'a> SessionStore<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn append_message(
        &self,
        key: &MasterKey,
        session_id: &str,
        role: &str,
        content: &str,
        finish_reason: Option<&str>,
    ) -> Result<String, ShadowError> {
        let id = uuid::Uuid::new_v4().to_string();
        let sealed = key.seal(content.as_bytes())?;
        let now = now_unix();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO message
                (id, session_id, role, content_enc, content_plain,
                 finish_reason, created_at)
             VALUES (?1,?2,?3,?4,0,?5,?6)",
            rusqlite::params![id, session_id, role, sealed, finish_reason, now],
        )?;
        tx.execute(
            "UPDATE session SET updated_at = ?2 WHERE id = ?1",
            rusqlite::params![session_id, now],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn messages(
        &self,
        key: &MasterKey,
        session_id: &str,
    ) -> Result<Vec<Message>, ShadowError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, role, content_enc, finish_reason, created_at
             FROM message WHERE session_id = ?1 ORDER BY created_at")?;
        let rows = stmt.query_map([session_id], |r| {
            let sealed: Vec<u8> = r.get(3)?;
            let bytes = key.open_sealed(&sealed)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let content = String::from_utf8(bytes)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            Ok(Message {
                id: r.get(0)?,
                session_id: r.get(1)?,
                role: r.get(2)?,
                content,
                finish_reason: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn create_session(
        &self,
        user_id: &str,
        model_id: &str,
        title: &str,
    ) -> Result<String, ShadowError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO session (id, user_id, title, model_id, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?5)",
            rusqlite::params![id, user_id, model_id, title, now],
        )?;
        Ok(id)
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<SessionMeta>, ShadowError> {
        let row = self.conn.query_row(
            "SELECT id, user_id, title, model_id, created_at, updated_at
             FROM session WHERE id = ?1",
            [session_id],
            |r| Ok(SessionMeta {
                id: r.get(0)?,
                user_id: r.get(1)?,
                title: r.get(2)?,
                model_id: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
            }),
        ).optional()?;
        Ok(row)
    }

    pub fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionMeta>, ShadowError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, title, model_id, created_at, updated_at
             FROM session WHERE user_id = ?1 AND archived = 0
             ORDER BY updated_at DESC")?;
        let rows = stmt.query_map([user_id], |r| Ok(SessionMeta {
            id: r.get(0)?,
            user_id: r.get(1)?,
            title: r.get(2)?,
            model_id: r.get(3)?,
            created_at: r.get(4)?,
            updated_at: r.get(5)?,
        }))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

/// Schreibt ein Audit-Event (Admin-Aktionen: export, model.switch, ...).
pub fn audit(
    conn: &Connection,
    actor: &str,
    action: &str,
    target: &str,
    detail: serde_json::Value,
) -> Result<(), ShadowError> {
    conn.execute(
        "INSERT INTO audit_event (id, timestamp, actor, action, target, detail_json)
         VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            uuid::Uuid::new_v4().to_string(),
            now_unix(),
            actor,
            action,
            target,
            detail.to_string(),
        ],
    )?;
    Ok(())
}
