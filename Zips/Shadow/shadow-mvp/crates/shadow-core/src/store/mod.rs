use rusqlite::Connection;
use crate::error::ShadowError;

pub mod schema {
    pub const V1: &str = include_str!("schema.sql");
}

/// Öffnet (oder erstellt) den Shadow-Store und führt Migrationen aus.
pub fn open(path: &std::path::Path) -> Result<Connection, ShadowError> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<(), ShadowError> {
    use rusqlite::OptionalExtension;
    let version: i64 = conn.query_row(
        "SELECT version FROM schema_meta LIMIT 1",
        [],
        |r| r.get(0),
    ).optional()?.unwrap_or(0);

    if version < 1 {
        conn.execute_batch(schema::V1)?;
    }
    if version < 2 {
        migrate_v2(conn)?;
    }
    Ok(())
}

/// Schema v2: User-Accounts bekommen Passwort-Hashes, E-Mail,
/// Pflicht-Passwort-Change (First-Login) und optionalen Kill-Switch.
/// `password_hash IS NULL` = Account ohne Login (Legacy, z. B. local-admin).
fn migrate_v2(conn: &Connection) -> Result<(), ShadowError> {
    let has_pw: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('user') WHERE name = 'password_hash'",
        [],
        |r| r.get(0),
    )?;
    if has_pw == 0 {
        conn.execute_batch(
            "ALTER TABLE user ADD COLUMN password_hash TEXT;
             ALTER TABLE user ADD COLUMN email TEXT;
             ALTER TABLE user ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE user ADD COLUMN kill_switch_hash TEXT;",
        )?;
    }
    conn.execute("UPDATE schema_meta SET version = 2", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_v1_to_v2() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(schema::V1).unwrap();
        conn.execute("UPDATE schema_meta SET version = 1", []).unwrap();
        migrate_v2(&conn).unwrap();
        let v: i64 = conn.query_row("SELECT version FROM schema_meta", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 2);
        // Idempotent:
        migrate_v2(&conn).unwrap();
    }
}
