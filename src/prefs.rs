//! User preferences persistence.
//!
//! Saves user preferences (like theme) to ~/.config/ttl/config.toml

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// User preferences
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Prefs {
    /// Selected theme name
    pub theme: Option<String>,
    /// Wide mode expands columns on wide terminals
    pub wide_mode: Option<bool>,
    /// PeeringDB API key for higher rate limits on IX detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peeringdb_api_key: Option<String>,
}

impl Prefs {
    /// Get config file path: ~/.config/ttl/config.toml
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("ttl").join("config.toml"))
    }

    /// Load preferences from disk (returns default if missing/invalid)
    pub fn load() -> Self {
        Self::path()
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Save preferences to disk
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(path) = Self::path() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, toml::to_string_pretty(self)?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefs_default() {
        let prefs = Prefs::default();
        assert!(prefs.theme.is_none());
        assert!(prefs.wide_mode.is_none());
        assert!(prefs.peeringdb_api_key.is_none());
    }

    #[test]
    fn test_prefs_serialization() {
        let prefs = Prefs {
            theme: Some("dracula".to_string()),
            wide_mode: Some(true),
            peeringdb_api_key: Some("test_api_key_123".to_string()),
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        assert!(toml_str.contains("theme = \"dracula\""));
        assert!(toml_str.contains("wide_mode = true"));
        assert!(toml_str.contains("peeringdb_api_key = \"test_api_key_123\""));

        let loaded: Prefs = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.theme, Some("dracula".to_string()));
        assert_eq!(loaded.wide_mode, Some(true));
        assert_eq!(
            loaded.peeringdb_api_key,
            Some("test_api_key_123".to_string())
        );
    }

    #[test]
    fn test_prefs_api_key_omitted_when_none() {
        let prefs = Prefs {
            theme: Some("default".to_string()),
            wide_mode: None,
            peeringdb_api_key: None,
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        // peeringdb_api_key should be omitted when None
        assert!(!toml_str.contains("peeringdb_api_key"));
    }
}
