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
    let version: i64 = conn.query_row(
        "SELECT version FROM schema_meta LIMIT 1",
        [],
        |r| r.get(0),
    ).optional()?.unwrap_or(0);

    if version < 1 {
        conn.execute_batch(schema::V1)?;
    }
    // Zukünftige Migrationen: if version < 2 { ... }
    Ok(())
}
