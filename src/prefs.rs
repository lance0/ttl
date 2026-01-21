//! User preferences persistence.
//!
//! Saves user preferences (like theme) to ~/.config/ttl/config.toml

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Display mode for column widths
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisplayMode {
    /// Auto-fit columns to content (default)
    #[default]
    Auto,
    /// Minimal column widths
    Compact,
    /// Generous column widths
    Wide,
}

impl DisplayMode {
    /// Cycle to next display mode
    pub fn next(self) -> Self {
        match self {
            Self::Auto => Self::Compact,
            Self::Compact => Self::Wide,
            Self::Wide => Self::Auto,
        }
    }

    /// Get display label for this mode
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Compact => "compact",
            Self::Wide => "wide",
        }
    }
}

/// User preferences
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Prefs {
    /// Selected theme name
    pub theme: Option<String>,
    /// Display mode for column widths (auto/compact/wide)
    pub display_mode: Option<DisplayMode>,
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
        assert!(prefs.display_mode.is_none());
        assert!(prefs.peeringdb_api_key.is_none());
    }

    #[test]
    fn test_prefs_serialization() {
        let prefs = Prefs {
            theme: Some("dracula".to_string()),
            display_mode: Some(DisplayMode::Wide),
            peeringdb_api_key: Some("test_api_key_123".to_string()),
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        assert!(toml_str.contains("theme = \"dracula\""));
        assert!(toml_str.contains("display_mode = \"wide\""));
        assert!(toml_str.contains("peeringdb_api_key = \"test_api_key_123\""));

        let loaded: Prefs = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.theme, Some("dracula".to_string()));
        assert_eq!(loaded.display_mode, Some(DisplayMode::Wide));
        assert_eq!(
            loaded.peeringdb_api_key,
            Some("test_api_key_123".to_string())
        );
    }

    #[test]
    fn test_prefs_api_key_omitted_when_none() {
        let prefs = Prefs {
            theme: Some("default".to_string()),
            display_mode: None,
            peeringdb_api_key: None,
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        // peeringdb_api_key should be omitted when None
        assert!(!toml_str.contains("peeringdb_api_key"));
    }

    #[test]
    fn test_display_mode_cycling() {
        assert_eq!(DisplayMode::Auto.next(), DisplayMode::Compact);
        assert_eq!(DisplayMode::Compact.next(), DisplayMode::Wide);
        assert_eq!(DisplayMode::Wide.next(), DisplayMode::Auto);
    }

    #[test]
    fn test_display_mode_labels() {
        assert_eq!(DisplayMode::Auto.label(), "auto");
        assert_eq!(DisplayMode::Compact.label(), "compact");
        assert_eq!(DisplayMode::Wide.label(), "wide");
    }

    #[test]
    fn test_display_mode_default_is_auto() {
        assert_eq!(DisplayMode::default(), DisplayMode::Auto);
    }

    #[test]
    fn test_display_mode_full_cycle() {
        // Verify cycling returns to start after 3 steps
        let start = DisplayMode::Auto;
        let after_one = start.next();
        let after_two = after_one.next();
        let after_three = after_two.next();
        assert_eq!(after_three, start);
    }

    #[test]
    fn test_display_mode_serialization_all_variants() {
        // Test Auto
        let prefs = Prefs {
            theme: None,
            display_mode: Some(DisplayMode::Auto),
            peeringdb_api_key: None,
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        assert!(toml_str.contains("display_mode = \"auto\""));
        let loaded: Prefs = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.display_mode, Some(DisplayMode::Auto));

        // Test Compact
        let prefs = Prefs {
            theme: None,
            display_mode: Some(DisplayMode::Compact),
            peeringdb_api_key: None,
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        assert!(toml_str.contains("display_mode = \"compact\""));
        let loaded: Prefs = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.display_mode, Some(DisplayMode::Compact));

        // Test Wide
        let prefs = Prefs {
            theme: None,
            display_mode: Some(DisplayMode::Wide),
            peeringdb_api_key: None,
        };
        let toml_str = toml::to_string_pretty(&prefs).unwrap();
        assert!(toml_str.contains("display_mode = \"wide\""));
        let loaded: Prefs = toml::from_str(&toml_str).unwrap();
        assert_eq!(loaded.display_mode, Some(DisplayMode::Wide));
    }

    #[test]
    fn test_display_mode_equality() {
        assert_eq!(DisplayMode::Auto, DisplayMode::Auto);
        assert_eq!(DisplayMode::Compact, DisplayMode::Compact);
        assert_eq!(DisplayMode::Wide, DisplayMode::Wide);
        assert_ne!(DisplayMode::Auto, DisplayMode::Compact);
        assert_ne!(DisplayMode::Auto, DisplayMode::Wide);
        assert_ne!(DisplayMode::Compact, DisplayMode::Wide);
    }

    #[test]
    fn test_display_mode_copy() {
        let mode = DisplayMode::Auto;
        let copied = mode; // Copy
        assert_eq!(mode, copied); // Original still usable (Copy trait)
    }

    #[test]
    fn test_prefs_missing_display_mode_defaults_to_none() {
        // Simulate old config without display_mode field
        let toml_str = r#"
            theme = "default"
        "#;
        let loaded: Prefs = toml::from_str(toml_str).unwrap();
        assert_eq!(loaded.theme, Some("default".to_string()));
        assert!(loaded.display_mode.is_none());
    }
}
