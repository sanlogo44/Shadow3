//! Shadow CLI – MVP-Skeleton.
//! Baut bewusst KEINE Modell-Logik; alles läuft über shadow_core.

use shadow_core::crypto::MasterKey;
use shadow_core::model::{
    GenConstraints, GenParams, GenerateRequest, MessageInput, ModelAdapter, ModelConfig,
    ModelEntry, ModelRegistry, PythonAdapter, StubAdapter, StreamEvent,
};
use shadow_core::session::{audit, SessionStore};
use shadow_core::store;
use shadow_core::{
    keystore_initialize, keystore_is_initialized, keystore_unlock,
    sha256_bytes, sha256_file,
};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data_dir = std::path::PathBuf::from(
        std::env::var("SHADOW_DATA_DIR").unwrap_or_else(|_| "./shadow-data".into()),
    );
    std::fs::create_dir_all(&data_dir).expect("data dir");

    let db_path = data_dir.join("shadow.db");
    let conn = store::open(&db_path).expect("open store");

    match args.get(1).map(String::as_str) {
        Some("init") => cmd_init(&conn),
        Some("models") => cmd_models(&conn),
        Some("doctor") => cmd_doctor(&db_path),
        Some("chat") => cmd_chat(&conn, args.get(2).map(String::as_str).unwrap_or("stub")),
        Some("sessions") => cmd_sessions(&conn),
        Some("export") => match args.get(2) {
            Some(sid) => cmd_export(&conn, sid, export_path(&data_dir, sid)),
            None => { eprintln!("Usage: export <session_id>"); std::process::exit(2); }
        },
        _ => {
            eprintln!("Befehle: init | models | doctor | sessions | export <session_id> | chat [model_id]");
            std::process::exit(2);
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn password_or_warn() -> String {
    std::env::var("SHADOW_PASSWORD").unwrap_or_else(|_| {
        eprintln!("WARN: SHADOW_PASSWORD nicht gesetzt — nutze Entwicklungs-Passwort.");
        "dev-only-not-secure".into()
    })
}

/// Entsperrt den Keystore; initialisiert ihn beim ersten Lauf (dev-freundlich).
fn open_keystore(conn: &rusqlite::Connection) -> MasterKey {
    let pw = password_or_warn();
    if keystore_is_initialized(conn).expect("keystore check") {
        keystore_unlock(conn, &pw).expect("keystore unlock (falsches Passwort?)")
    } else {
        keystore_initialize(conn, &pw).expect("keystore init")
    }
}

fn export_path(data_dir: &std::path::Path, session_id: &str) -> PathBuf {
    data_dir.join(format!("export-{session_id}.json"))
}

fn cmd_init(conn: &rusqlite::Connection) {
    conn.execute(
        "INSERT OR IGNORE INTO user (id, name, role, created_at)
         VALUES ('local-admin', 'Local Admin', 'admin', ?1)",
        [now()],
    ).expect("seed user");

    let reg = ModelRegistry::new(conn);
    reg.upsert(&ModelEntry::new("stub", "stub", "Deterministischer Stub"))
        .expect("seed stub");
    let mut py = ModelEntry::new("python-echo", "python-echo", "Python Echo (AI Layer)");
    py.capabilities_json = serde_json::json!({"note": "via shadow_ai Prozess"});
    reg.upsert(&py).expect("seed python-echo");

    // Keystore gleich mit anlegen, damit init == "fertig einrichten".
    open_keystore(conn);
    println!("OK: Store + Keystore initialisiert ({} aktive Modelle)",
             reg.list_enabled().unwrap().len());
}

fn cmd_models(conn: &rusqlite::Connection) {
    let reg = ModelRegistry::new(conn);
    for m in reg.list_enabled().expect("list models") {
        println!("{}  [{}]  export={}", m.model_id, m.adapter_type, m.export_allowed);
    }
}

/// Erwartet Modell-Datei-Hash aus adapter_config.weights_path/sha256.
fn configured_model_file(entry: &ModelEntry) -> Option<(PathBuf, String)> {
    let cfg = entry.capabilities_json.as_object()?;
    let path = cfg.get("weights_path")?.as_str()?;
    let sha = cfg.get("sha256")?.as_str()?;
    Some((PathBuf::from(path), sha.to_string()))
}

fn cmd_doctor(db_path: &std::path::Path) {
    let conn = match store::open(db_path) {
        Ok(c) => c,
        Err(e) => { eprintln!("FAIL: Store nicht lesbar: {e}"); std::process::exit(1); }
    };
    let mut problems = 0;

    // 1) DB-Integritaet (SQLite-Quick-Check)
    match conn.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0)) {
        Ok(s) if s == "ok" => println!("OK   DB quick_check"),
        other => { println!("FAIL DB quick_check: {other:?}"); problems += 1; }
    }

    // 2) Keystore vorhanden?
    match keystore_is_initialized(&conn) {
        Ok(true) => println!("OK   Keystore initialisiert"),
        Ok(false) => { println!("WARN Keystore fehlt — `shadow init` ausführen"); problems += 1; }
        Err(e) => { println!("FAIL Keystore: {e}"); problems += 1; }
    }

    // 3) Modell-Datei-Hashes (Tamper Detection)
    let reg = ModelRegistry::new(&conn);
    for m in reg.list_enabled().expect("models") {
        if let Some((path, expected)) = configured_model_file(&m) {
            if !path.exists() {
                println!("FAIL {}: Datei fehlt ({})", m.model_id, path.display());
                problems += 1;
            } else {
                match sha256_file(&path) {
                    Ok(actual) if actual == expected => {
                        println!("OK   {}: Hash stimmt", m.model_id);
                    }
                    Ok(actual) => {
                        println!("FAIL {}: Hash mismatch\n  erwartet {expected}\n  ist      {actual}");
                        problems += 1;
                    }
                    Err(e) => { println!("FAIL {}: {e}", m.model_id); problems += 1; }
                }
            }
        }
    }

    if problems > 0 {
        println!("\n{problems} Problem(e) — siehe FAIL/Zeilen oben.");
        std::process::exit(1);
    }
    println!("\nAlles in Ordnung.");
}

fn cmd_sessions(conn: &rusqlite::Connection) {
    let store = SessionStore::new(conn);
    for s in store.list_sessions("local-admin").expect("sessions") {
        println!("{}  {}  model={}  updated={}",
                 s.id, s.title, s.model_id, s.updated_at);
    }
}

/// Exportiert eine Session als JSON. Exportkontrolle: nur wenn das
/// Session-Modell export_allowed=true hat. Jeder Export wird auditiert.
fn cmd_export(conn: &rusqlite::Connection, session_id: &str, out: PathBuf) {
    let store = SessionStore::new(conn);
    let session = match store.get_session(session_id).expect("session") {
        Some(s) => s,
        None => { eprintln!("Session {session_id} nicht gefunden."); std::process::exit(1); }
    };

    let reg = ModelRegistry::new(conn);
    let entry = reg.get(&session.model_id).expect("registry")
        .unwrap_or_else(|| ModelEntry::new(&session.model_id, "?", "?"));

    let detail = serde_json::json!({"session": session_id, "model": session.model_id});
    if !entry.export_allowed {
        audit(conn, "local-admin", "export.denied", session_id, detail)
            .expect("audit");
        eprintln!("Export VERWEIGERT: Modell '{}' ist nicht exportierbar (export_allowed=false).",
                  session.model_id);
        std::process::exit(1);
    }

    let key = open_keystore(conn);
    let messages = store.messages(&key, session_id).expect("messages");

    let export = serde_json::json!({
        "format": "shadow-export/v1",
        "session": session,
        "exported_at": now(),
        "messages": messages,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&export).unwrap())
        .expect("write export");

    audit(conn, "local-admin", "export", session_id,
          serde_json::json!({"file": out.to_string_lossy(), "bytes":
              std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0)}))
        .expect("audit");
    println!("Export geschrieben: {} (SHA-256 {})",
             out.display(), sha256_bytes(&std::fs::read(&out).unwrap()));
}

fn cmd_chat(conn: &rusqlite::Connection, model_id: &str) {
    let reg = ModelRegistry::new(conn);
    let entry = match reg.get(model_id).expect("registry") {
        Some(e) if e.enabled => e,
        _ => {
            eprintln!("Modell '{model_id}' nicht aktiviert. `shadow init` ausführen?");
            std::process::exit(1);
        }
    };

    let mut adapter: Box<dyn ModelAdapter> = match entry.adapter_type.as_str() {
        "stub" => Box::new(StubAdapter::new()),
        "python-echo" => {
            let mut py = PythonAdapter::shadow_ai_default();
            // SHADOW_AI_DIR auf den Prozess vererben, damit `import shadow_ai` klappt.
            if let Ok(dir) = std::env::var("SHADOW_AI_DIR") {
                py = PythonAdapter::new(vec![
                    "python3".into(), "-c".into(),
                    format!(
                        "import sys, runpy; sys.path.insert(0, {dir:?}); \
                         runpy.run_module('shadow_ai', run_name='__main__')"
                    ),
                ]);
            }
            Box::new(py)
        }
        other => {
            eprintln!("Adapter '{other}' im MVP nicht verfügbar.");
            std::process::exit(1);
        }
    };
    adapter.load(&ModelConfig {
        model_id: entry.model_id.clone(),
        adapter_config: entry.capabilities_json.clone(),
        expected_sha256: None,
    }).expect("adapter load");

    let key = open_keystore(conn);
    let sessions = SessionStore::new(conn);
    let sid = sessions
        .create_session("local-admin", model_id, "CLI-Chat")
        .expect("create session");
    println!("Session {sid} — leere Eingabe beendet (/exit).");

    let stdin = std::io::stdin();
    let mut history: Vec<MessageInput> = Vec::new();
    loop {
        print!("> ");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        if stdin.read_line(&mut line).unwrap() == 0 { break; }
        let input = line.trim();
        if input.is_empty() || input == "/exit" { break; }

        sessions.append_message(&key, &sid, "user", input, None)
            .expect("persist user msg");
        history.push(MessageInput { role: "user".into(), content: input.into() });

        let req = GenerateRequest {
            session_id: sid.clone(),
            messages: history.clone(),
            params: GenParams::default(),
            constraints: GenConstraints::default(),
        };

        let mut reply = String::new();
        let res = adapter.stream(req, Box::new(|ev| match ev {
            StreamEvent::Token { text, .. } => {
                reply.push_str(&text);
                print!("{text}");
                std::io::stdout().flush().unwrap();
            }
            StreamEvent::Usage { .. } => {}
            StreamEvent::Finish { reason } => println!("\n[{reason:?}]"),
        })).expect("stream");

        sessions.append_message(
            &key, &sid, "assistant", &reply,
            Some(&format!("{:?}", res.finish_reason)),
        ).expect("persist assistant msg");
        history.push(MessageInput { role: "assistant".into(), content: reply });
    }
}
