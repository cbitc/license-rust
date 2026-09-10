use sha2::{Digest, Sha256};

use crate::error::LicenseError;

pub fn current_fingerprint() -> Result<String, LicenseError> {
    let machine_id = platform_machine_id().unwrap_or_default();
    let host = hostname::get()
        .map_err(|error| LicenseError::Fingerprint(error.to_string()))?
        .to_string_lossy()
        .into_owned();
    Ok(hash_components(&[
        std::env::consts::OS,
        std::env::consts::ARCH,
        &machine_id,
        &host,
    ]))
}

fn hash_components(parts: &[&str]) -> String {
    let normalized = parts
        .iter()
        .map(|part| part.trim().to_lowercase())
        .collect::<Vec<_>>()
        .join("\u{1f}");
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

#[cfg(windows)]
fn platform_machine_id() -> Option<String> {
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .ok()?
        .get_value("MachineGuid")
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_hides_inputs() {
        let first = hash_components(&[" Windows ", "X86_64", "Secret-Machine", "Host"]);
        let second = hash_components(&["windows", "x86_64", "secret-machine", "host"]);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(!first.contains("secret"));
    }

    #[test]
    fn current_fingerprint_is_hex_sha256() {
        let fingerprint = current_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
