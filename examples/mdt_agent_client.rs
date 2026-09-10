use license_sdk::{LicenseError, LicenseEnvironment, DEFAULT_ISSUER};
use serde::Deserialize;

/// 策略 meta 中按产品自定义的数据，客户端按需定义结构体。
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TtsConstraint {
    max_version: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Meta {
    #[serde(rename = "TTS")]
    tts: TtsConstraint,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 打开本地许可环境（license-active 写入的共享库），离线校验当前环境。
    let environment = LicenseEnvironment::open_default()?;

    match license_sdk::verify_environment(&environment, DEFAULT_ISSUER) {
        Ok(Some(license)) => {
            println!("环境已激活（来源: {:?}）", license.source);
            println!(
                "产品: {} ({})",
                license.claims.product_name, license.claims.product_code
            );
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
            // meta 按产品自定义，需要时反序列化
            if let Ok(meta) = serde_json::from_value::<Meta>(license.claims.meta.clone()) {
                println!("TTS 最大版本: {}", meta.tts.max_version);
            }
        }
        Ok(None) => {
            println!("当前环境未激活，请先运行 license-active 完成激活");
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
