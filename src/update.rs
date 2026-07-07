//! Update notification support
//!
//! Checks GitHub releases for new versions (cached, 1h interval).
//! Detects install method and shows appropriate update command.
//!
//! The check can be opted out of via `--no-update-check`, the `DO_NOT_TRACK`
//! or `TTL_NO_UPDATE_CHECK` env vars, a `no_update_check = true` preference, or
//! by building without the default `update-check` feature.

/// Whether update checking was compiled in (the `update-check` feature, on by
/// default). Package builds can drop it with `--no-default-features`, which also
/// removes the `update-informer` dependency from the tree.
pub const ENABLED: bool = cfg!(feature = "update-check");

/// True when the user opted out of the update check via environment:
/// `DO_NOT_TRACK` (the cross-tool standard, <https://consoledonottrack.com>) or
/// `TTL_NO_UPDATE_CHECK`.
pub fn env_opt_out() -> bool {
    ["DO_NOT_TRACK", "TTL_NO_UPDATE_CHECK"]
        .iter()
        .any(|var| std::env::var(var).is_ok_and(|v| flag_is_truthy(&v)))
}

/// A set env var counts as opt-out unless it's explicitly falsey (empty, "0",
/// or "false"). We err toward *not* phoning home when the value is ambiguous.
fn flag_is_truthy(v: &str) -> bool {
    !matches!(v.trim(), "" | "0" | "false")
}

/// Resolve whether the background update check should be skipped, honoring
/// precedence (higher layer wins): compiled-out > env opt-out > CLI flag >
/// saved `no_update_check` preference.
///
/// `pref` is tristate: `Some(true)` opts out, `Some(false)` explicitly keeps
/// the check on, and `None` (unset) falls back to the compiled-in default
/// (enabled). ttl stores its config and TUI-saved prefs in one `config.toml`,
/// so there is a single preference layer here (xfr splits config vs. prefs).
pub fn check_disabled(env_opt_out: bool, cli_flag: bool, pref: Option<bool>) -> bool {
    !ENABLED || env_opt_out || cli_flag || pref.unwrap_or(false)
}

/// How ttl was installed (best guess based on binary path)
#[derive(Debug, Clone, Copy)]
pub enum InstallMethod {
    Homebrew,
    Cargo,
    Binary, // GitHub release or unknown
}

impl InstallMethod {
    /// Detect install method from executable path
    pub fn detect() -> Self {
        let exe_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok());

        let Some(path) = exe_path else {
            return Self::Binary;
        };

        let path_str = path.to_string_lossy();

        if path_str.contains("homebrew") || path_str.contains("Cellar") {
            Self::Homebrew
        } else if path_str.contains(".cargo/bin") {
            Self::Cargo
        } else {
            Self::Binary
        }
    }

    /// Get the appropriate update command for this install method
    pub fn update_command(&self) -> &'static str {
        match self {
            Self::Homebrew => "brew upgrade ttl",
            Self::Cargo => "cargo install ttl",
            Self::Binary => "github.com/lance0/ttl/releases",
        }
    }

    /// Get cached install method (detected once per process)
    pub fn cached() -> Self {
        use std::sync::OnceLock;
        static INSTALL_METHOD: OnceLock<InstallMethod> = OnceLock::new();
        *INSTALL_METHOD.get_or_init(Self::detect)
    }
}

/// Check GitHub for a newer version
///
/// Returns Some(new_version) if an update is available.
/// Returns None if no update available or check failed.
/// Uses interval(ZERO) to always perform a network check — we only call this
/// once per process lifetime (in a background thread), so cache-based rate
/// limiting is unnecessary.
#[cfg(feature = "update-check")]
pub fn check_for_update() -> Option<String> {
    use std::time::Duration;
    use update_informer::{Check, registry::GitHub};

    let informer = update_informer::new(GitHub, "lance0/ttl", env!("CARGO_PKG_VERSION"))
        .interval(Duration::ZERO);

    informer
        .check_version()
        .ok()
        .flatten()
        .map(|v| v.to_string())
}

/// No-op stub when built without the `update-check` feature.
#[cfg(not(feature = "update-check"))]
pub fn check_for_update() -> Option<String> {
    None
}

/// Print update notification to stderr
pub fn print_update_notice(new_version: &str) {
    let method = InstallMethod::detect();
    let current = env!("CARGO_PKG_VERSION");
    let command = method.update_command();

    // Use ASCII box drawing for reliable terminal alignment
    // Unicode arrows and box characters have variable widths across terminals
    let version_line = format!("Update available: {} -> {}", current, new_version);
    let command_line = format!("Run: {}", command);
    let width = version_line.len().max(command_line.len()) + 4;

    eprintln!();
    eprintln!("\x1b[33m+{}+\x1b[0m", "-".repeat(width));
    eprintln!(
        "\x1b[33m|\x1b[0m  {:<width$}\x1b[33m|\x1b[0m",
        version_line,
        width = width - 2
    );
    eprintln!(
        "\x1b[33m|\x1b[0m  {:<width$}\x1b[33m|\x1b[0m",
        command_line,
        width = width - 2
    );
    eprintln!("\x1b[33m+{}+\x1b[0m", "-".repeat(width));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_is_truthy() {
        for on in ["1", "true", "yes", "on", " 1 "] {
            assert!(flag_is_truthy(on), "{on:?} should count as opt-out");
        }
        for off in ["", "  ", "0", "false"] {
            assert!(!flag_is_truthy(off), "{off:?} should not count as opt-out");
        }
    }

    #[test]
    fn test_check_disabled_precedence() {
        // The tristate resolution only matters when the check is compiled in.
        if !ENABLED {
            assert!(check_disabled(false, false, Some(false)));
            return;
        }
        // Saved pref governs when env/CLI are quiet.
        assert!(check_disabled(false, false, Some(true))); // opt out
        assert!(!check_disabled(false, false, Some(false))); // explicitly on
        assert!(!check_disabled(false, false, None)); // default on
        // env or CLI opt-out wins over an explicit pref "on".
        assert!(check_disabled(true, false, Some(false)));
        assert!(check_disabled(false, true, Some(false)));
    }

    #[test]
    fn test_install_method_commands() {
        assert_eq!(InstallMethod::Homebrew.update_command(), "brew upgrade ttl");
        assert_eq!(InstallMethod::Cargo.update_command(), "cargo install ttl");
        assert!(
            InstallMethod::Binary
                .update_command()
                .contains("github.com")
        );
    }
}
