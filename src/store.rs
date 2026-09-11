use std::path::PathBuf;

use directories::ProjectDirs;
use rusqlite::{Connection, OpenFlags};

use crate::{claims::StoredLicense, error::LicenseError};

pub trait ActivationStore {
    fn load_activation(&self) -> Result<Option<StoredLicense>, LicenseError>;
}

#[derive(Clone, Debug)]
pub struct DbActivationStore {
    path: PathBuf,
}

impl DbActivationStore {
    pub(crate) fn locate_default() -> Result<Self, LicenseError> {
        Ok(Self {
            path: default_store_path()?,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn locate(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn with_read_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, LicenseError>,
    ) -> Result<T, LicenseError> {
        let connection = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| LicenseError::Environment(error.to_string()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(3))
            .map_err(|error| LicenseError::Storage(error.to_string()))?;
        operation(&connection)
    }
}

impl ActivationStore for DbActivationStore {
    fn load_activation(&self) -> Result<Option<StoredLicense>, LicenseError> {
        match self.path.try_exists() {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(error) => return Err(LicenseError::Environment(error.to_string())),
        }
        self.with_read_connection(|connection| {
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
}

fn default_store_path() -> Result<PathBuf, LicenseError> {
    let project_dirs = ProjectDirs::from("com", "license-tools", "license-active")
        .ok_or_else(|| LicenseError::Environment("无法确定应用数据目录".to_owned()))?;
    Ok(project_dirs.data_local_dir().join("license.db"))
}

pub fn default_store() -> Result<Box<dyn ActivationStore>, LicenseError> {
    Ok(Box::new(DbActivationStore::locate_default()?))
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    use crate::claims::ActivationSource;

    #[test]
    fn missing_database_means_not_activated_and_creates_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested").join("license.db");
        let environment = DbActivationStore::locate(path.clone());
        assert!(environment.load_activation().unwrap().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn reads_activation_written_by_activation_entry() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("license.db");
        let writer = Connection::open(&path).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE activation (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    activation_json TEXT NOT NULL
                 );",
            )
            .unwrap();
        let stored = StoredLicense {
            token: "token".into(),
            source: ActivationSource::Online,
            activated_at: 100,
        };
        writer
            .execute(
                "INSERT INTO activation (id, activation_json) VALUES (1, ?1)",
                params![serde_json::to_string(&stored).unwrap()],
            )
            .unwrap();
        drop(writer);

        let environment = DbActivationStore::locate(path);
        assert_eq!(
            environment.load_activation().unwrap().unwrap().token,
            "token"
        );
    }
}
