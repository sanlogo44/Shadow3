# Shadow – MVP-Skeleton

Plattform-unabhängige AI-Plattform: Rust Core + austauschbare Modell-Adapter
(in-Prozess Stub, Python AI Layer per JSONL/stdio), SQLite-Store mit
verschlüsselten Sessions (Argon2id + AES-256-GCM), Keystore, Audit-Log,
Tamper Detection via SHA-256, Exportkontrolle.

## Layout

```
crates/shadow-core   Adapter-Trait, Stub/Python-Adapter, Registry,
                     Store, Keystore, Krypto, Session-Store
crates/shadow-cli    init | models | doctor | sessions | export | chat
shadow-ai/           Python AI Layer (Shadow Node Protocol v1, JSONL/stdio)
```

## Schnellstart

```bash
# 1) Toolchain vorausgesetzt: Rust (cargo), Python 3.10+
export SHADOW_PASSWORD="test-passwort"
export SHADOW_DATA_DIR="$PWD/data"
export SHADOW_AI_DIR="$PWD/shadow-ai"     # für chat python-echo

# 2) Build & Test
cargo test -p shadow-core                 # Stub- + Adapter-Tests
cd shadow-ai && python3 -m unittest discover -s tests && cd ..

# 3) Einrichten & nutzen
cargo run -p shadow-cli -- init
cargo run -p shadow-cli -- doctor
cargo run -p shadow-cli -- chat stub
cargo run -p shadow-cli -- chat python-echo
cargo run -p shadow-cli -- sessions
cargo run -p shadow-cli -- export <session_id>
```

## Modell-Datei-Hashes (Tamper Detection)

Einem Registry-Eintrag über `capabilities_json` beibringen:

```json
{"weights_path": "/pfad/model.bin", "sha256": "<hex>"}
```

`doctor` verifiziert dann Hash und Datei-Existenz. Fehlt das Paar,
wird das Modell nicht geprüft (Stub/Echo brauchen es nicht).

## Exportkontrolle

Export ist nur möglich, wenn das Session-Modell `export_allowed=true` in der
Registry hat. Jeder Export (erfolgreich oder verweigert) landet im Audit-Log.
Das Schema-Feld `content_plain` existiert nur für Stub/Debug und ist im
Normalbetrieb 0.

## Protokoll

`shadow-ai/shadow_ai/protocol.py` — NDJSON über stdio, Versions-Handshake,
normierte Fehlercodes, kooperativer Abbruch via cancel.
