//! Datei-Integritaet: SHA-256 fuer Modell-Dateien und Exporte.

use sha2::{Digest, Sha256};
use crate::error::ShadowError;

pub fn sha256_file(path: &std::path::Path) -> Result<String, ShadowError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
