//! User preferences persistence.
//!
//! Saves user preferences (like theme) to ~/.config/ttl/config.toml

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// User preferences
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Prefs {
    /// Selected theme name
    pub theme: Option<String>,
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
    }

    #[test]
    fn test_prefs_serialization() {
        let prefs = Prefs {
            theme: Some("dracula".to_string()),
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        assert!(toml_str.contains("theme = \"dracula\""));

        let loaded: Prefs = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.theme, Some("dracula".to_string()));
    }
}
