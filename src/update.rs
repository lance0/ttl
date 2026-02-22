//! Update notification support
//!
//! Checks GitHub releases for new versions (cached, 1h interval).
//! Detects install method and shows appropriate update command.

use update_informer::registry::GitHub;

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
pub fn check_for_update() -> Option<String> {
    use std::time::Duration;
    use update_informer::Check;

    let informer = update_informer::new(GitHub, "lance0/ttl", env!("CARGO_PKG_VERSION"))
        .interval(Duration::ZERO);

    informer
        .check_version()
        .ok()
        .flatten()
        .map(|v| v.to_string())
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
