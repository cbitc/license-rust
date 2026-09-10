use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use rusqlite::{Connection, params};

use crate::{
    claims::{PublicJwk, StoredLicense},
    error::LicenseError,
};

/// 与 license-active 内置的信任公钥一致（kid 2026.08.05）。
/// 校验时与本地缓存公钥按 kid 合并（缓存优先），保证全新环境也能验证由该密钥签发的令牌。
pub const BUILTIN_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"SdQb9d4-MW-rM91EUUrHEnVhv3-MfyymX0o_cWc3UXk","kid":"2026.08.05","alg":"EdDSA","use":"sig"}"#;

/// 本地许可环境：license-active 写入、各客户端共享读取的 SQLite 库。
///
/// 路径与表结构和 license-active 完全一致
/// （`ProjectDirs::from("com","license-tools","license-active").data_local_dir()/license.db`）。
#[derive(Clone, Debug)]
pub struct LicenseEnvironment {
    path: PathBuf,
}

impl LicenseEnvironment {
    /// 打开默认共享环境（license-active 使用的同一路径）。
    pub fn open_default() -> Result<Self, LicenseError> {
        Self::open(default_environment_path()?)
    }

    /// 打开指定路径的环境库（会按需创建目录、数据表）。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LicenseError> {
        let environment = Self {
            path: path.as_ref().to_owned(),
        };
        if let Some(parent) = environment.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| LicenseError::Environment(error.to_string()))?;
        }
        environment.with_connection(|connection| {
            connection
                .execute_batch(
                    "PRAGMA journal_mode=WAL;
                     PRAGMA foreign_keys=ON;
                     CREATE TABLE IF NOT EXISTS signing_keys (
                        kid TEXT PRIMARY KEY,
                        jwk_json TEXT NOT NULL,
                        updated_at INTEGER NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS activation (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        activation_json TEXT NOT NULL
                     );",
                )
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            Ok(())
        })?;
        Ok(environment)
    }

    /// 读取当前激活记录（仅令牌本体与两个本地事实，claims 需校验后从令牌解析）。
    pub fn load_activation(&self) -> Result<Option<StoredLicense>, LicenseError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT activation_json FROM activation WHERE id = 1")
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            let mut rows = statement
                .query([])
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            match rows
                .next()
                .map_err(|error| LicenseError::Storage(error.to_string()))?
            {
                Some(row) => {
                    let json: String = row
                        .get(0)
                        .map_err(|error| LicenseError::Storage(error.to_string()))?;
                    serde_json::from_str(&json)
                        .map_err(|error| LicenseError::Storage(error.to_string()))
                }
                None => Ok(None),
            }
        })
    }

    /// 写入激活记录（供激活入口等写入方使用；覆盖单行记录）。
    pub fn save_activation(&self, license: &StoredLicense) -> Result<(), LicenseError> {
        let json = serde_json::to_string(license)
            .map_err(|error| LicenseError::Storage(error.to_string()))?;
        self.with_connection(|connection| {
            let transaction = connection
                .unchecked_transaction()
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            transaction
                .execute(
                    "INSERT INTO activation (id, activation_json) VALUES (1, ?1)
                     ON CONFLICT(id) DO UPDATE SET activation_json = excluded.activation_json",
                    [&json],
                )
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            transaction
                .commit()
                .map_err(|error| LicenseError::Storage(error.to_string()))
        })
    }

    /// 清除激活记录。
    pub fn clear_activation(&self) -> Result<(), LicenseError> {
        self.with_connection(|connection| {
            connection
                .execute("DELETE FROM activation WHERE id = 1", [])
                .map(|_| ())
                .map_err(|error| LicenseError::Storage(error.to_string()))
        })
    }

    /// 读取本地缓存的签名公钥（不含内置公钥；校验入口会自动合并）。
    pub fn load_keys(&self) -> Result<Vec<PublicJwk>, LicenseError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT jwk_json FROM signing_keys")
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            let mut keys = Vec::new();
            for row in rows {
                let json = row.map_err(|error| LicenseError::Storage(error.to_string()))?;
                let key: PublicJwk = serde_json::from_str(&json)
                    .map_err(|error| LicenseError::Storage(error.to_string()))?;
                keys.push(key);
            }
            Ok(keys)
        })
    }

    /// 覆盖/合并写入签名公钥（供激活入口刷新密钥缓存使用）。
    pub fn save_keys(&self, keys: &[PublicJwk]) -> Result<(), LicenseError> {
        self.with_connection(|connection| {
            let transaction = connection
                .unchecked_transaction()
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            for key in keys {
                transaction
                    .execute(
                        "INSERT INTO signing_keys (kid, jwk_json, updated_at)
                         VALUES (?1, ?2, unixepoch())
                         ON CONFLICT(kid) DO UPDATE SET
                           jwk_json = excluded.jwk_json,
                           updated_at = excluded.updated_at",
                        params![
                            key.kid,
                            serde_json::to_string(key)
                                .map_err(|error| LicenseError::Storage(error.to_string()))?
                        ],
                    )
                    .map_err(|error| LicenseError::Storage(error.to_string()))?;
            }
            transaction
                .commit()
                .map_err(|error| LicenseError::Storage(error.to_string()))
        })
    }

    /// 读取缓存公钥并合并内置公钥：同 kid 时缓存优先（更新的密钥轮换数据）。
    pub(crate) fn load_keys_with_builtin(&self) -> Result<Vec<PublicJwk>, LicenseError> {
        let mut keys = self.load_keys()?;
        let builtin: PublicJwk = serde_json::from_str(BUILTIN_JWK)
            .map_err(|error| LicenseError::Storage(error.to_string()))?;
        if !keys.iter().any(|key| key.kid == builtin.kid) {
            keys.push(builtin);
        }
        Ok(keys)
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, LicenseError>,
    ) -> Result<T, LicenseError> {
        let connection = Connection::open(&self.path)
            .map_err(|error| LicenseError::Environment(error.to_string()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(3))
            .map_err(|error| LicenseError::Storage(error.to_string()))?;
        operation(&connection)
    }
}

fn default_environment_path() -> Result<PathBuf, LicenseError> {
    let project_dirs = ProjectDirs::from("com", "license-tools", "license-active")
        .ok_or_else(|| LicenseError::Environment("无法确定应用数据目录".to_owned()))?;
    Ok(project_dirs.data_local_dir().join("license.db"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ActivationSource;

    fn stored(token: &str) -> StoredLicense {
        StoredLicense {
            token: token.to_owned(),
            source: ActivationSource::Offline,
            activated_at: 100,
        }
    }

    #[test]
    fn activation_round_trip_and_clear() {
        let temp = tempfile::tempdir().unwrap();
        let environment = LicenseEnvironment::open(temp.path().join("test.db")).unwrap();
        assert!(environment.load_activation().unwrap().is_none());

        environment.save_activation(&stored("first")).unwrap();
        environment.save_activation(&stored("second")).unwrap();
        assert_eq!(
            environment.load_activation().unwrap().unwrap().token,
            "second"
        );

        environment.clear_activation().unwrap();
        assert!(environment.load_activation().unwrap().is_none());
    }

    #[test]
    fn builtin_key_is_merged_with_cached_priority() {
        let temp = tempfile::tempdir().unwrap();
        let environment = LicenseEnvironment::open(temp.path().join("test.db")).unwrap();

        let mut keys = environment.load_keys_with_builtin().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.remove(0).kid, "2026.08.05");

        let cached = PublicJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            kid: "2026.08.05".into(),
            alg: Some("EdDSA".into()),
            key_use: Some("sig".into()),
        };
        environment.save_keys(&[cached.clone()]).unwrap();
        let keys = environment.load_keys_with_builtin().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].x, cached.x);
    }
}
