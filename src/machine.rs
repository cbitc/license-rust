#[cfg(windows)]
use winreg::{
    RegKey,
    enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY},
};

fn normalize_machine_guid(value: &str) -> Result<String, String> {
    let normalized = value
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim()
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("Windows MachineGuid 为空".to_owned());
    }
    Ok(normalized)
}

#[cfg(windows)]
pub fn read_machine_guid() -> Result<String, String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cryptography = hklm
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Cryptography",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .map_err(|error| format!("无法打开 Windows MachineGuid 注册表项: {error}"))?;
    let value: String = cryptography
        .get_value("MachineGuid")
        .map_err(|error| format!("无法读取 Windows MachineGuid: {error}"))?;
    normalize_machine_guid(&value)
}

#[cfg(not(windows))]
pub fn read_machine_guid() -> Result<String, String> {
    Err("测试客户端仅支持 Windows".to_owned())
}

#[cfg(test)]
mod tests {
    use super::normalize_machine_guid;

    #[test]
    fn normalizes_machine_guid_for_signing_and_verification() {
        assert_eq!(
            normalize_machine_guid("  {A0B1C2D3-E4F5-4678-9ABC-DEF012345678}  ").unwrap(),
            "a0b1c2d3-e4f5-4678-9abc-def012345678"
        );
    }

    #[test]
    fn rejects_empty_machine_guid() {
        assert!(normalize_machine_guid(" { } ").is_err());
    }
}
