# license-sdk

用于本地软件离线授权校验的 Rust SDK。客户端通过 SDK 从**本地许可环境**（由激活入口 [license-active](http://192.168.1.252:3000/cbitc/license-active) 写入的共享数据库）读取离线令牌，在完全离线的情况下完成签名验证、有效期校验、设备指纹比对，判断当前环境是否已获得许可。

## v0.2 破坏性变更

- 对接 license-api 的 **version 3** 令牌格式（`entitlements` 为 `{code, name, expiresAt?}` 对象数组，新增 `licenseKey`/`productCode`/`productName`/`policyName`/`issuedAt` 声明）。v0.1 的 v2 格式与旧 `.lic` 离线文件流程已随服务端下线而移除。
- 移除 `VerifierBuilder`/`Verifier`/`decoding_key`/`read_machine_guid` 及 PEM 信封解析，改为**环境校验**模型：`LicenseEnvironment` + `verify_environment`。
- 指纹算法与激活入口完全一致（`OS + 架构 + 平台机器标识 + 主机名` 的 SHA-256，跨平台）；不再对指纹二次哈希。
- 校验语义与激活入口镜像：严格校验 `version == 3`、`nbf <= now < exp`（无宽容秒数）、签发方、必要声明、设备指纹原始字符串相等。

## 安装

在应用的 `Cargo.toml` 中添加：

```toml
[dependencies]
license-sdk = { git = "http://192.168.1.252:3000/cbitc/license-sdk-rust.git", tag = "v0.2.0" }
```

## 快速开始

```rust
use license_sdk::{LicenseError, LicenseEnvironment, DEFAULT_ISSUER};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let environment = LicenseEnvironment::open_default()?;

    match license_sdk::verify_environment(&environment, DEFAULT_ISSUER) {
        Ok(Some(license)) => {
            println!("环境已激活（来源: {:?}）", license.source);
            println!(
                "产品: {} ({})",
                license.claims.product_name, license.claims.product_code
            );
            println!(
                "授权功能: {:?}",
                license.claims.entitlements.iter().map(|e| e.code.as_str()).collect::<Vec<_>>()
            );
            println!("令牌有效期至: {}", license.claims.exp);
        }
        Ok(None) => println!("当前环境未激活，请先运行 license-active 完成激活"),
        Err(LicenseError::Expired) => println!("离线令牌已过期，请重新激活"),
        Err(LicenseError::FingerprintMismatch) => println!("令牌不属于当前设备"),
        Err(error) => println!("环境校验失败: {error}"),
    }
    Ok(())
}
```

完整可运行示例见 `examples/mdt_agent_client.rs`（`cargo run --example mdt_agent_client`）。

`claims.meta` 是策略自定义元数据（`serde_json::Value`），客户端按需定义结构体反序列化：

```rust
#[derive(serde::Deserialize)]
struct LicenseMeta {
    #[serde(rename = "TTS")]
    tts: TtsConstraint,
}
let meta: LicenseMeta = serde_json::from_value(license.claims.meta.clone())?;
```

## 本地许可环境契约

| 项 | 值 |
| --- | --- |
| 数据库路径 | `ProjectDirs::from("com", "license-tools", "license-active").data_local_dir()/license.db`（Windows 为 `%LOCALAPPDATA%\license-tools\license-active\data\license.db`） |
| 写入方 | license-active 激活入口（bind 成功后写入令牌，同时缓存服务端签名公钥） |
| 读取方 | 任意集成本 SDK 的客户端（WAL 模式，支持并发读） |
| 激活记录 | 单行 JSON：`{ token, source: "online"/"offline", activated_at }`，claims 等派生信息不落库 |
| 签名公钥 | 本地缓存 + SDK 内置信任公钥（kid `2026.08.05`）按 kid 合并，缓存优先 |

SDK 的 `verify_environment` **只读不写**：校验失败的令牌不会被清除（清除是激活入口的策略），客户端可将 `Err` 一律视为未许可处理。

## API 参考

### `LicenseEnvironment`

| 方法 | 说明 |
| --- | --- |
| `open_default()` | 打开默认共享环境库（license-active 使用的路径），按需创建目录与表。 |
| `open(path)` | 打开指定路径的环境库（测试用）。 |
| `load_activation()` | 读取激活记录 `Option<StoredLicense>`（令牌本体 + 来源 + 激活时间）。 |
| `save_activation(&StoredLicense)` | 写入/覆盖激活记录（供激活入口等写入方使用）。 |
| `clear_activation()` | 清除激活记录。 |
| `load_keys()` / `save_keys(&[PublicJwk])` | 读取/合并写入本地缓存的签名公钥。 |

### `verify_environment`

```rust
pub fn verify_environment(
    environment: &LicenseEnvironment,
    expected_issuer: &str,
) -> Result<Option<VerifiedLicense>, LicenseError>
```

高层入口：读取环境令牌 → 计算当前设备指纹 → 合并公钥缓存与内置公钥 → 验签并校验 claims。

- `Ok(None)`：环境中没有激活令牌（未激活）。
- `Ok(Some(VerifiedLicense))`：校验通过。`VerifiedLicense` 含 `token`、`source`、`activated_at`、`claims`（从令牌新鲜解析，非本地副本）、`fingerprint`。
- `Err(LicenseError)`：令牌存在但校验失败，令牌保持原样。

### `verify_certificate`

```rust
pub fn verify_certificate(
    compact: &str,
    keys: &[PublicJwk],
    expected_issuer: &str,
    fingerprint: &str,
    now: i64,
) -> Result<Claims, LicenseError>
```

校验原语：对给定的紧凑 JWS 验签并校验 v3 claims。时间由调用方注入（便于测试），适合激活入口等需要自定义密钥来源/时钟的场景。

### 其它

| 项 | 说明 |
| --- | --- |
| `current_fingerprint()` | 计算当前环境指纹，与激活入口、服务端令牌中的 `fingerprintSha256` 同格式。 |
| `DEFAULT_ISSUER` | 默认签发者标识 `MDT_LICENSE_SERVER`，与服务端、激活入口默认值一致。 |
| `Claims` | v3 全量声明（camelCase 反序列化），含 `license_key`、`product_code`、`product_name`、`policy_name`、`issued_at`、`entitlements: Vec<EntitlementClaim>`、`meta` 等。 |

### `LicenseError`

| 错误 | 含义 |
| --- | --- |
| `Environment(message)` | 无法确定或打开本地环境数据（数据目录、数据库）。 |
| `Storage(message)` | 本地数据库读写失败。 |
| `Fingerprint(message)` | 设备指纹计算失败（如无法获取主机名）。 |
| `TokenFormat` | 令牌不是合法的三段式 JWS。 |
| `TokenAlgorithm` | 令牌头部算法/类型不受支持（要求 `EdDSA` + `license+jwt`）。 |
| `SigningKeyMissing` | 找不到令牌 `kid` 对应的签名公钥。 |
| `SigningKeyInvalid(message)` | 签名公钥类型、编码或长度无效。 |
| `TokenPayload` | 令牌 payload 无法解码为 v3 claims。 |
| `Signature` | Ed25519 签名验证失败，令牌被篡改。 |
| `Version` | 令牌版本不受支持（仅支持 version 3）。 |
| `Issuer` | 令牌签发方与预期不符。 |
| `MissingClaims` | 令牌缺少必要声明。 |
| `Entitlements` | 令牌授权项无效。 |
| `NotYetValid` | 令牌尚未到生效时间。 |
| `Expired` | 令牌已过期。 |
| `TimeRange` | 令牌声明的时间范围自相矛盾。 |
| `FingerprintMismatch` | 令牌绑定的设备指纹与当前环境不符。 |

## 安全说明

- 离线校验信任三样东西：Ed25519 签名（内置公钥 + 激活入口缓存的公钥）、本地运行环境、客户端系统时钟。服务器与本机时钟偏移过大会导致 `NotYetValid`/`Expired`。
- SDK 只验证签名完整性和许可证规则，无法保证客户端环境不被篡改。

## 测试许可获取

以下流程仅用于测试：

1. 启动 license-api 与 license-active，将 `LICENSE_API_URL` 指向测试服务。
2. 在管理端创建产品、功能权限和许可策略，签发许可证得到 license key。
3. 在目标机器运行 license-active 完成在线激活（bind → issue → 本地写入令牌）。
4. 运行集成本 SDK 的客户端，`verify_environment` 应返回许可信息。

提示：若不使用产品参与校验，可使用产品 "ANY" 表示逻辑上的"包含所有产品"，将许可策略设置为永不过期、各模块分别过期，实现分模块不分产品的效果。

<img src="./license流程.drawio.svg" alt="license 流程"/>
