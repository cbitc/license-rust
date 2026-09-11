use license_sdk::LicenseError;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match license_sdk::verify_environment() {
        Ok(license) => {
            println!("环境已激活");
            println!("许可证密钥: {}", license.claims.license_key);
            println!(
                "授权功能: {:?}",
                license
                    .claims
                    .entitlements
                    .iter()
                    .map(|item| item.code.as_str())
                    .collect::<Vec<_>>()
            );
            println!("令牌有效期至: {}", license.claims.exp);
        }
        Err(LicenseError::Inactive) => {
            println!("当前环境未激活，请先运行激活程序完成激活");
        }
        Err(LicenseError::FingerprintMismatch) => {
            println!("令牌不属于当前设备");
        }
        Err(LicenseError::Expired) => {
            println!("离线令牌已过期，请重新激活");
        }
        Err(error) => {
            println!("环境校验失败: {error}");
        }
    }

    Ok(())
}
