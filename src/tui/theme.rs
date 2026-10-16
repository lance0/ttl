//! Color theme definitions for the UI.
//!
//! Provides 11 built-in themes: default, kawaii, cyber, dracula, monochrome,
//! matrix, nord, gruvbox, catppuccin, tokyo_night, solarized.
//! Themes can be selected via the `--theme` CLI flag.

use ratatui::style::Color;
use std::borrow::Cow;

/// All themeable colors in the application
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Theme {
    name: Cow<'static, str>,

    // UI chrome
    pub border: Color,
    pub border_focused: Color,
    pub text: Color,
    pub text_dim: Color,
    pub highlight_bg: Color,

    // Status indicators
    pub success: Color, // low loss (<10%)
    pub warning: Color, // medium loss (10-50%)
    pub error: Color,   // high loss (>50%), timeout

    // Accents
    pub shortcut: Color, // keyboard hints
    pub header: Color,   // title text
}

impl Default for Theme {
    fn default() -> Self {
        Self::default_theme()
    }
}

impl Theme {
    /// The default theme - matches the original ttl colors
    pub fn default_theme() -> Self {
        Self {
            name: Cow::Borrowed("default"),

            // UI chrome - original ttl used Cyan for borders
            border: Color::Cyan,
            border_focused: Color::Cyan,
            // Reset keeps the terminal's own foreground, so the default theme
            // reads on light and dark terminals alike.
            text: Color::Reset,
            text_dim: Color::DarkGray,
            highlight_bg: Color::DarkGray,

            // Status indicators
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,

            // Accents
            shortcut: Color::Yellow,
            header: Color::Cyan,
        }
    }

    /// Kawaii theme - cute pastel colors
    pub fn kawaii() -> Self {
        Self {
            name: Cow::Borrowed("kawaii"),

            border: Color::Rgb(255, 182, 214), // Pink
            border_focused: Color::Rgb(255, 182, 214),
            text: Color::Rgb(255, 255, 255),
            text_dim: Color::Rgb(180, 180, 200),
            highlight_bg: Color::Rgb(60, 50, 70),

            success: Color::Rgb(152, 255, 200), // Mint
            warning: Color::Rgb(255, 200, 152), // Peach
            error: Color::Rgb(255, 121, 162),   // Soft pink

            shortcut: Color::Rgb(214, 182, 255), // Lavender
            header: Color::Rgb(255, 182, 214),   // Pink
        }
    }

    /// Cyber/Futuristic theme - neon on dark
    pub fn cyber() -> Self {
        Self {
            name: Cow::Borrowed("cyber"),

            border: Color::Rgb(0, 255, 255), // Cyan neon
            border_focused: Color::Rgb(0, 255, 255),
            text: Color::Rgb(255, 255, 255),
            text_dim: Color::Rgb(121, 121, 138),
            highlight_bg: Color::Rgb(20, 20, 35),

            success: Color::Rgb(0, 255, 150), // Neon green
            warning: Color::Rgb(255, 200, 0), // Neon yellow
            error: Color::Rgb(255, 50, 100),  // Neon red-pink

            shortcut: Color::Rgb(255, 0, 255), // Magenta neon
            header: Color::Rgb(0, 255, 255),   // Cyan neon
        }
    }

    /// Dracula theme - popular dark theme
    pub fn dracula() -> Self {
        Self {
            name: Cow::Borrowed("dracula"),

            border: Color::Rgb(189, 147, 249), // Purple
            border_focused: Color::Rgb(189, 147, 249),
            text: Color::Rgb(248, 248, 242),      // Foreground
            text_dim: Color::Rgb(133, 146, 184),  // Comment, lifted for contrast
            highlight_bg: Color::Rgb(68, 71, 90), // Current line

            success: Color::Rgb(80, 250, 123),  // Green
            warning: Color::Rgb(255, 184, 108), // Orange
            error: Color::Rgb(255, 85, 85),     // Red

            shortcut: Color::Rgb(241, 250, 140), // Yellow
            header: Color::Rgb(255, 121, 198),   // Pink
        }
    }

    /// Monochrome theme - grayscale only
    pub fn monochrome() -> Self {
        Self {
            name: Cow::Borrowed("monochrome"),

            border: Color::Rgb(200, 200, 200),
            border_focused: Color::Rgb(200, 200, 200),
            text: Color::Rgb(255, 255, 255),
            text_dim: Color::Rgb(120, 120, 120),
            highlight_bg: Color::Rgb(50, 50, 50),

            success: Color::Rgb(200, 200, 200), // Light gray
            warning: Color::Rgb(170, 170, 170), // Medium gray
            error: Color::Rgb(255, 255, 255),   // White (stands out)

            shortcut: Color::Rgb(200, 200, 200),
            header: Color::Rgb(255, 255, 255),
        }
    }

    /// Matrix theme - green on black hacker style
    pub fn matrix() -> Self {
        Self {
            name: Cow::Borrowed("matrix"),

            border: Color::Rgb(0, 255, 0), // Bright green
            border_focused: Color::Rgb(0, 255, 0),
            text: Color::Rgb(0, 255, 0),
            text_dim: Color::Rgb(0, 170, 60),
            highlight_bg: Color::Rgb(0, 20, 0),

            success: Color::Rgb(0, 255, 0),     // Bright green
            warning: Color::Rgb(200, 255, 100), // Yellow-green
            error: Color::Rgb(255, 100, 100),   // Red (stands out)

            shortcut: Color::Rgb(100, 255, 100), // Light green
            header: Color::Rgb(0, 255, 0),
        }
    }

    /// Nord theme - arctic, north-bluish colors
    pub fn nord() -> Self {
        Self {
            name: Cow::Borrowed("nord"),

            border: Color::Rgb(136, 192, 208), // Nord8 cyan
            border_focused: Color::Rgb(136, 192, 208),
            text: Color::Rgb(236, 239, 244),      // Nord6
            text_dim: Color::Rgb(147, 158, 178),  // Nord3, lifted for contrast
            highlight_bg: Color::Rgb(59, 66, 82), // Nord1

            success: Color::Rgb(163, 190, 140), // Nord14 green
            warning: Color::Rgb(235, 203, 139), // Nord13 yellow
            error: Color::Rgb(191, 97, 106),    // Nord11 red

            shortcut: Color::Rgb(235, 203, 139), // Nord13 yellow
            header: Color::Rgb(136, 192, 208),   // Nord8 cyan
        }
    }

    /// Gruvbox theme - retro groove colors
    pub fn gruvbox() -> Self {
        Self {
            name: Cow::Borrowed("gruvbox"),

            border: Color::Rgb(254, 128, 25), // Orange
            border_focused: Color::Rgb(254, 128, 25),
            text: Color::Rgb(235, 219, 178),      // fg
            text_dim: Color::Rgb(168, 153, 132),  // fg4
            highlight_bg: Color::Rgb(80, 73, 69), // bg2

            success: Color::Rgb(184, 187, 38), // Green
            warning: Color::Rgb(250, 189, 47), // Yellow
            error: Color::Rgb(251, 73, 52),    // Red

            shortcut: Color::Rgb(250, 189, 47), // Yellow
            header: Color::Rgb(254, 128, 25),   // Orange
        }
    }

    /// Catppuccin Mocha theme - soothing pastel colors
    pub fn catppuccin() -> Self {
        Self {
            name: Cow::Borrowed("catppuccin"),

            border: Color::Rgb(203, 166, 247), // Mauve
            border_focused: Color::Rgb(203, 166, 247),
            text: Color::Rgb(205, 214, 244),       // Text
            text_dim: Color::Rgb(147, 153, 178),   // Overlay2
            highlight_bg: Color::Rgb(88, 91, 112), // Surface2

            success: Color::Rgb(166, 227, 161), // Green
            warning: Color::Rgb(249, 226, 175), // Yellow
            error: Color::Rgb(243, 139, 168),   // Red

            shortcut: Color::Rgb(249, 226, 175), // Yellow
            header: Color::Rgb(245, 194, 231),   // Pink
        }
    }

    /// Tokyo Night theme - dark theme inspired by Tokyo city lights
    pub fn tokyo_night() -> Self {
        Self {
            name: Cow::Borrowed("tokyo_night"),

            border: Color::Rgb(187, 154, 247), // Purple
            border_focused: Color::Rgb(187, 154, 247),
            text: Color::Rgb(192, 202, 245),      // Foreground
            text_dim: Color::Rgb(125, 132, 164),  // Comment, lifted for contrast
            highlight_bg: Color::Rgb(59, 66, 97), // bg_highlight

            success: Color::Rgb(158, 206, 106), // Green
            warning: Color::Rgb(224, 175, 104), // Yellow
            error: Color::Rgb(247, 118, 142),   // Red

            shortcut: Color::Rgb(224, 175, 104), // Yellow
            header: Color::Rgb(187, 154, 247),   // Purple
        }
    }

    /// Solarized Dark theme - precision colors for readability
    pub fn solarized() -> Self {
        Self {
            name: Cow::Borrowed("solarized"),

            border: Color::Rgb(42, 161, 152), // Cyan
            border_focused: Color::Rgb(42, 161, 152),
            text: Color::Rgb(147, 161, 161),     // base1
            text_dim: Color::Rgb(131, 148, 150), // base0
            highlight_bg: Color::Rgb(7, 54, 66), // base02

            success: Color::Rgb(133, 153, 0), // Green
            warning: Color::Rgb(181, 137, 0), // Yellow
            error: Color::Rgb(220, 50, 47),   // Red

            shortcut: Color::Rgb(181, 137, 0), // Yellow
            header: Color::Rgb(203, 75, 22),   // Orange
        }
    }

    /// Preserve each palette's hue while giving every selected-row foreground
    /// at least 4.5:1 contrast against its known RGB selection background.
    /// ANSI colors remain terminal controlled; their actual RGB values are unknown.
    pub fn for_selection(&self) -> Self {
        let mut selected = self.clone();
        for foreground in [
            &mut selected.text,
            &mut selected.text_dim,
            &mut selected.success,
            &mut selected.warning,
            &mut selected.error,
            &mut selected.shortcut,
            &mut selected.header,
        ] {
            *foreground = readable_on(*foreground, self.highlight_bg);
        }
        selected
    }

    /// Loss severity: quiet at zero, plain text for any loss, then warning
    /// and error. Loss is never green, so color always means "look here".
    pub fn loss_color(&self, loss_pct: f64) -> Color {
        if loss_pct >= 20.0 {
            self.error
        } else if loss_pct >= 5.0 {
            self.warning
        } else if loss_pct > 0.0 {
            self.text
        } else {
            self.text_dim
        }
    }

    /// Get a theme by name
    pub fn by_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "kawaii" => Self::kawaii(),
            "cyber" | "futuristic" => Self::cyber(),
            "monochrome" | "mono" => Self::monochrome(),
            "dracula" => Self::dracula(),
            "matrix" | "hacker" => Self::matrix(),
            "nord" => Self::nord(),
            "gruvbox" => Self::gruvbox(),
            "catppuccin" | "mocha" => Self::catppuccin(),
            "tokyo_night" | "tokyo" | "tokyonight" => Self::tokyo_night(),
            "solarized" => Self::solarized(),
            _ => Self::default_theme(),
        }
    }

    /// Get the theme name
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// List all available theme names
    #[allow(dead_code)]
    pub fn list() -> &'static [&'static str] {
        &[
            "default",
            "kawaii",
            "cyber",
            "dracula",
            "monochrome",
            "matrix",
            "nord",
            "gruvbox",
            "catppuccin",
            "tokyo_night",
            "solarized",
        ]
    }
}

/// Relative luminance and contrast follow the sRGB definition used by W3C.
/// This is a readability target for the known color pair, not a claim about
/// accessibility of a user's terminal or its configurable ANSI palette.
fn luminance(rgb: [u8; 3]) -> f64 {
    let linear = rgb.map(|channel| {
        let value = f64::from(channel) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    });
    linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722
}

fn contrast(a: [u8; 3], b: [u8; 3]) -> f64 {
    let (a, b) = (luminance(a), luminance(b));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

fn readable_on(foreground: Color, background: Color) -> Color {
    // The default theme's DarkGray selection bar is dark in every common
    // palette, so the terminal foreground (dark on light terminals) and the
    // DarkGray dim text would vanish on it.
    if background == Color::DarkGray {
        match foreground {
            Color::Reset => return Color::White,
            Color::DarkGray => return Color::Gray,
            _ => {}
        }
    }
    let (Color::Rgb(r, g, b), Color::Rgb(br, bg, bb)) = (foreground, background) else {
        return foreground;
    };
    let original = [r, g, b];
    let backdrop = [br, bg, bb];
    if contrast(original, backdrop) >= 4.5 {
        return foreground;
    }
    let target = if contrast([255; 3], backdrop) >= contrast([0; 3], backdrop) {
        255
    } else {
        0
    };
    let blend = |amount: u16| {
        original.map(|c| ((u16::from(c) * (255 - amount) + target * amount) / 255) as u8)
    };
    let (mut low, mut high) = (0, 255);
    while low < high {
        let middle = (low + high) / 2;
        if contrast(blend(middle), backdrop) >= 4.5 {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let [r, g, b] = blend(low);
    Color::Rgb(r, g, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rgb_themes_keep_selected_text_and_status_colors_readable() {
        for name in Theme::list() {
            let theme = Theme::by_name(name).for_selection();
            let Color::Rgb(r, g, b) = theme.highlight_bg else {
                continue;
            };
            for color in [
                theme.text,
                theme.text_dim,
                theme.success,
                theme.warning,
                theme.error,
                theme.shortcut,
                theme.header,
            ] {
                let Color::Rgb(fr, fg, fb) = color else {
                    panic!("RGB theme has ANSI foreground");
                };
                assert!(
                    contrast([fr, fg, fb], [r, g, b]) >= 4.5,
                    "{name}: {color:?}"
                );
            }
        }
    }

    #[test]
    fn selection_adjustment_supports_light_backgrounds_and_preserves_ansi() {
        assert!(contrast([0; 3], [255; 3]) > 20.9);
        assert_eq!(readable_on(Color::White, Color::DarkGray), Color::White);
        let Color::Rgb(r, g, b) = readable_on(Color::Rgb(240, 240, 240), Color::Rgb(255, 255, 255))
        else {
            unreachable!()
        };
        assert!(contrast([r, g, b], [255; 3]) >= 4.5);
        assert_eq!(
            readable_on(Color::Rgb(255, 255, 255), Color::Rgb(0, 0, 0)),
            Color::Rgb(255, 255, 255)
        );
    }

    #[test]
    fn dim_text_stays_readable_on_each_themes_intended_background() {
        // RGB themes do not paint a background; these are the dark terminal
        // backgrounds each palette is designed for.
        let backgrounds = [
            ("kawaii", [40, 30, 45]),
            ("cyber", [10, 10, 20]),
            ("dracula", [40, 42, 54]),
            ("monochrome", [0, 0, 0]),
            ("matrix", [0, 0, 0]),
            ("nord", [46, 52, 64]),
            ("gruvbox", [40, 40, 40]),
            ("catppuccin", [30, 30, 46]),
            ("tokyo_night", [26, 27, 38]),
            ("solarized", [0, 43, 54]),
        ];
        assert_eq!(backgrounds.len(), Theme::list().len() - 1);
        for (name, bg) in backgrounds {
            let theme = Theme::by_name(name);
            for color in [theme.text, theme.text_dim] {
                let Color::Rgb(r, g, b) = color else {
                    panic!("{name}: ANSI color")
                };
                assert!(contrast([r, g, b], bg) >= 4.5, "{name}: {color:?}");
            }
        }
    }

    #[test]
    fn default_theme_follows_terminal_foreground_and_stays_readable_selected() {
        let theme = Theme::default();
        assert_eq!(theme.text, Color::Reset);
        let selected = theme.for_selection();
        assert_eq!(selected.text, Color::White);
        assert_eq!(selected.text_dim, Color::Gray);
    }

    #[test]
    fn loss_color_thresholds() {
        let theme = Theme::dracula();
        assert_eq!(theme.loss_color(0.0), theme.text_dim);
        assert_eq!(theme.loss_color(0.1), theme.text);
        assert_eq!(theme.loss_color(4.9), theme.text);
        assert_eq!(theme.loss_color(5.0), theme.warning);
        assert_eq!(theme.loss_color(19.9), theme.warning);
        assert_eq!(theme.loss_color(20.0), theme.error);
        assert_eq!(theme.loss_color(100.0), theme.error);
        for name in Theme::list() {
            let theme = Theme::by_name(name);
            for loss in [0.0, 1.0, 10.0, 50.0] {
                if theme.text == theme.success && loss < 5.0 {
                    continue; // matrix: all text is green
                }
                assert_ne!(theme.loss_color(loss), theme.success, "{name}");
            }
        }
    }

    #[test]
    fn test_by_name_default() {
        let theme = Theme::by_name("default");
        assert_eq!(theme.name(), "default");
        assert_eq!(theme.border, Color::Cyan);
    }

    #[test]
    fn test_by_name_unknown_returns_default() {
        let theme = Theme::by_name("unknown_theme");
        assert_eq!(theme.name(), "default");
    }

    #[test]
    fn test_by_name_case_insensitive() {
        let lower = Theme::by_name("kawaii");
        let upper = Theme::by_name("KAWAII");
        assert_eq!(lower.name(), upper.name());
    }

    #[test]
    fn test_cyber_alias() {
        let cyber = Theme::by_name("cyber");
        let futuristic = Theme::by_name("futuristic");
        assert_eq!(cyber.name(), "cyber");
        assert_eq!(futuristic.name(), "cyber");
    }

    #[test]
    fn test_matrix_alias() {
        let matrix = Theme::by_name("matrix");
        let hacker = Theme::by_name("hacker");
        assert_eq!(matrix.name(), "matrix");
        assert_eq!(hacker.name(), "matrix");
    }

    #[test]
    fn test_catppuccin_alias() {
        let catppuccin = Theme::by_name("catppuccin");
        let mocha = Theme::by_name("mocha");
        assert_eq!(catppuccin.name(), "catppuccin");
        assert_eq!(mocha.name(), "catppuccin");
    }

    #[test]
    fn test_tokyo_night_aliases() {
        assert_eq!(Theme::by_name("tokyo_night").name(), "tokyo_night");
        assert_eq!(Theme::by_name("tokyo").name(), "tokyo_night");
        assert_eq!(Theme::by_name("tokyonight").name(), "tokyo_night");
    }

    #[test]
    fn test_all_themes_have_distinct_colors() {
        for name in Theme::list() {
            let theme = Theme::by_name(name);
            // Each theme should have its success != error colors
            assert_ne!(
                format!("{:?}", theme.success),
                format!("{:?}", theme.error),
                "{} has same success and error colors",
                name
            );
        }
    }

    #[test]
    fn test_default_trait() {
        let theme = Theme::default();
        assert_eq!(theme.name(), "default");
    }
}
