//! Print-CLI chrome: Omarchy palette, Clack-style rail, gradient phase words.
//!
//! This is not a TUI. Output is ordinary lines. OSC-8 and Kitty graphics are
//! emitted only for an attended color TTY and degrade to plain text otherwise.

use colorgrad::{Color as GradColor, Gradient, GradientBuilder, LinearGradient};
use owo_colors::OwoColorize;
#[cfg(any(feature = "arch", test))]
use std::io::IsTerminal;
#[cfg(any(feature = "arch", test))]
use std::path::Path;
use std::sync::OnceLock;

const RAIL_GLYPH: &str = "│";
#[cfg(any(feature = "arch", test))]
const STRIPE_CELLS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Palette {
    pub accent: Rgb,
    pub muted: Rgb,
    pub cyan: Rgb,
    pub magenta: Rgb,
    pub green: Rgb,
    pub yellow: Rgb,
    pub red: Rgb,
    pub blue: Rgb,
}

impl Palette {
    /// Tokyo Night, Omarchy's default stock theme.
    const fn fallback() -> Self {
        Self {
            accent: Rgb {
                r: 0x7a,
                g: 0xa2,
                b: 0xf7,
            },
            muted: Rgb {
                r: 0x41,
                g: 0x48,
                b: 0x68,
            },
            cyan: Rgb {
                r: 0x44,
                g: 0x9d,
                b: 0xab,
            },
            magenta: Rgb {
                r: 0xad,
                g: 0x8e,
                b: 0xe6,
            },
            green: Rgb {
                r: 0x9e,
                g: 0xce,
                b: 0x6a,
            },
            yellow: Rgb {
                r: 0xe0,
                g: 0xaf,
                b: 0x68,
            },
            red: Rgb {
                r: 0xf7,
                g: 0x76,
                b: 0x8e,
            },
            blue: Rgb {
                r: 0x7a,
                g: 0xa2,
                b: 0xf7,
            },
        }
    }

    fn parse_toml(text: &str) -> Option<Self> {
        let table = toml::from_str::<toml::Table>(text).ok()?;
        let fallback = Self::fallback();
        Some(Self {
            accent: rgb_key(&table, "accent").unwrap_or(fallback.accent),
            muted: rgb_key(&table, "muted").unwrap_or(fallback.muted),
            cyan: rgb_key(&table, "cyan").unwrap_or(fallback.cyan),
            magenta: rgb_key(&table, "magenta").unwrap_or(fallback.magenta),
            green: rgb_key(&table, "green").unwrap_or(fallback.green),
            yellow: rgb_key(&table, "yellow").unwrap_or(fallback.yellow),
            red: rgb_key(&table, "red").unwrap_or(fallback.red),
            blue: rgb_key(&table, "blue").unwrap_or(fallback.blue),
        })
    }
}

fn rgb_key(table: &toml::Table, key: &str) -> Option<Rgb> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .and_then(parse_hex)
}

pub(crate) fn parse_hex(raw: &str) -> Option<Rgb> {
    let digits = raw.trim().trim_start_matches('#');
    match digits.len() {
        6 => {
            let value = u32::from_str_radix(digits, 16).ok()?;
            Some(Rgb {
                r: ((value >> 16) & 0xff) as u8,
                g: ((value >> 8) & 0xff) as u8,
                b: (value & 0xff) as u8,
            })
        }
        3 => {
            let value = u32::from_str_radix(digits, 16).ok()?;
            Some(Rgb {
                r: (((value >> 8) & 0xf) * 0x11) as u8,
                g: (((value >> 4) & 0xf) * 0x11) as u8,
                b: ((value & 0xf) * 0x11) as u8,
            })
        }
        _ => None,
    }
}

fn omarchy_colors_path() -> Option<std::path::PathBuf> {
    let home = home::home_dir()?;
    let path = home.join(".local/state/omarchy/current/theme/colors.toml");
    path.is_file().then_some(path)
}

fn load_palette() -> Palette {
    omarchy_colors_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| Palette::parse_toml(&text))
        .unwrap_or_else(Palette::fallback)
}

pub(crate) fn palette() -> Palette {
    static PALETTE: OnceLock<Palette> = OnceLock::new();
    *PALETTE.get_or_init(load_palette)
}

fn paint(text: &str, rgb: Rgb) -> String {
    text.truecolor(rgb.r, rgb.g, rgb.b).to_string()
}

fn paint_bold(text: &str, rgb: Rgb) -> String {
    text.truecolor(rgb.r, rgb.g, rgb.b).bold().to_string()
}

/// Vertical Clack rail in the theme muted color.
pub(crate) fn rail() -> String {
    if crate::cli::style::colors_enabled() {
        paint(RAIL_GLYPH, palette().muted)
    } else {
        "|".to_string()
    }
}

/// Accent-colored rail used for the active phase marker.
pub(crate) fn accent_rail() -> String {
    if crate::cli::style::colors_enabled() {
        paint_bold(RAIL_GLYPH, palette().accent)
    } else {
        "|".to_string()
    }
}

fn phase_gradient() -> Option<LinearGradient> {
    let palette = palette();
    GradientBuilder::new()
        .colors(&[
            GradColor::from_rgba8(palette.accent.r, palette.accent.g, palette.accent.b, 255),
            GradColor::from_rgba8(palette.cyan.r, palette.cyan.g, palette.cyan.b, 255),
            GradColor::from_rgba8(palette.magenta.r, palette.magenta.g, palette.magenta.b, 255),
        ])
        .build::<LinearGradient>()
        .ok()
}

/// Gradient the phase word across the Omarchy accent/cyan/magenta stops.
pub(crate) fn gradient_text(text: &str) -> String {
    if !crate::cli::style::colors_enabled() {
        return text.to_string();
    }
    let Some(gradient) = phase_gradient() else {
        return paint_bold(text, palette().accent);
    };
    let chars: Vec<char> = text.chars().collect();
    let last = chars.len().saturating_sub(1).max(1);
    chars
        .into_iter()
        .enumerate()
        .map(|(index, character)| {
            let [r, g, b, _] = gradient.at(index as f32 / last as f32).to_rgba8();
            character.to_string().truecolor(r, g, b).bold().to_string()
        })
        .collect()
}

#[cfg(any(feature = "arch", test))]
fn hyperlinks_enabled() -> bool {
    crate::cli::style::colors_enabled() && std::io::stdout().is_terminal()
}

#[cfg(any(feature = "arch", test))]
fn percent_encode_path(path: &str) -> String {
    path.bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'-' | b'_' | b'~' => {
                vec![byte]
            }
            _ => format!("%{byte:02X}").into_bytes(),
        })
        .map(char::from)
        .collect()
}

#[cfg(any(feature = "arch", test))]
fn osc8(url: &str, label: &str) -> String {
    if !hyperlinks_enabled() {
        return label.to_string();
    }
    format!("\u{1b}]8;;{url}\u{1b}\\{label}\u{1b}]8;;\u{1b}\\")
}

/// Clickable `file://` link when the terminal supports OSC-8.
#[cfg(any(feature = "arch", test))]
pub(crate) fn osc8_file(path: &Path, label: &str) -> String {
    let display = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let url = format!("file://{}", percent_encode_path(&display.to_string_lossy()));
    osc8(&url, label)
}

/// Clickable http(s) link. Rejects anything that is not http/https.
#[cfg(any(feature = "arch", test))]
pub(crate) fn osc8_http(url: &str, label: &str) -> String {
    let cleaned = crate::cli::style::sanitize_terminal_text(url);
    if cleaned.starts_with("https://") || cleaned.starts_with("http://") {
        osc8(&cleaned, label)
    } else {
        label.to_string()
    }
}

#[cfg(any(feature = "arch", test))]
fn graphics_capable() -> bool {
    if !crate::cli::style::colors_enabled() || !std::io::stdout().is_terminal() {
        return false;
    }
    if std::env::var_os("KITTY_WINDOW_ID").is_some() {
        return true;
    }
    let program = std::env::var("TERM_PROGRAM").unwrap_or_default();
    if matches!(
        program.as_str(),
        "ghostty" | "Ghostty" | "WezTerm" | "kitty" | "iTerm.app"
    ) {
        return true;
    }
    let term = std::env::var("TERM").unwrap_or_default();
    term.contains("kitty") || term.contains("ghostty")
}

#[cfg(any(feature = "arch", test))]
pub(crate) fn kitty_rgb_bar(pixels: &[[u8; 3]]) -> String {
    let width = pixels.len();
    let mut rgb = Vec::with_capacity(width * 3);
    for pixel in pixels {
        rgb.extend_from_slice(pixel);
    }
    let payload = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, rgb);
    format!("\u{1b}_Ga=T,f=24,s={width},v=1,c={width},r=1,q=2;{payload}\u{1b}\\")
}

#[cfg(any(feature = "arch", test))]
fn stripe_pixels(digest: &str) -> Vec<[u8; 3]> {
    let Some(gradient) = phase_gradient() else {
        let accent = palette().accent;
        return vec![[accent.r, accent.g, accent.b]; STRIPE_CELLS];
    };
    (0..STRIPE_CELLS)
        .map(|index| {
            let byte = digest.as_bytes().get(index).copied().unwrap_or(b'0');
            let t = (f32::from(byte) / 255.0 + index as f32 / STRIPE_CELLS as f32) * 0.5;
            let [r, g, b, _] = gradient.at(t).to_rgba8();
            [r, g, b]
        })
        .collect()
}

/// Visual fingerprint of a SHA-256. Kitty graphics when the terminal can
/// take them, otherwise a truecolor Unicode bar.
#[cfg(any(feature = "arch", test))]
pub(crate) fn digest_stripe(digest: &str) -> String {
    let pixels = stripe_pixels(digest);
    if !crate::cli::style::colors_enabled() {
        return "=".repeat(STRIPE_CELLS);
    }
    if graphics_capable() {
        return kitty_rgb_bar(&pixels);
    }
    pixels
        .into_iter()
        .map(|[r, g, b]| "▀".truecolor(r, g, b).to_string())
        .collect()
}

#[cfg(any(feature = "arch", test))]
const PKGBUILD_KEYS: &[&str] = &[
    "pkgname",
    "pkgver",
    "pkgrel",
    "pkgdesc",
    "url",
    "arch",
    "license",
    "depends",
    "makedepends",
    "checkdepends",
    "optdepends",
    "provides",
    "conflicts",
    "replaces",
    "source",
    "sha256sums",
    "sha512sums",
    "b2sums",
    "validpgpkeys",
    "install",
    "epoch",
    "pkgbase",
];

#[cfg(any(feature = "arch", test))]
fn assignment_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let name = trimmed.split(['=', '(']).next()?.trim();
    if name.is_empty() {
        return None;
    }
    name.chars()
        .all(|character| character == '_' || character.is_ascii_alphanumeric())
        .then_some(name)
}

/// Color PKGBUILD keywords, comments, and function names. Hand-rolled so the
/// binary does not take syntect's syntax dump for an eight-line preview.
#[cfg(any(feature = "arch", test))]
pub(crate) fn highlight_pkgbuild_line(line: &str) -> String {
    if !crate::cli::style::colors_enabled() {
        return line.to_string();
    }
    let palette = palette();
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return paint(line, palette.muted);
    }
    if let Some(name) = assignment_name(line)
        && PKGBUILD_KEYS.contains(&name)
        && let Some(index) = line.find(name)
    {
        let (prefix, rest) = line.split_at(index);
        let (keyword, suffix) = rest.split_at(name.len());
        let color = match name {
            "source" | "sha256sums" | "sha512sums" | "b2sums" | "install" | "validpgpkeys" => {
                palette.yellow
            }
            _ => palette.accent,
        };
        return format!("{prefix}{}{suffix}", paint_bold(keyword, color));
    }
    line.to_string()
}

/// rustc-style `  12 |  source=...` snippet line.
#[cfg(any(feature = "arch", test))]
pub(crate) fn snippet_line(number: usize, line: &str) -> String {
    let highlighted = highlight_pkgbuild_line(line);
    if crate::cli::style::colors_enabled() {
        format!(
            "  {} {:>4} {} {highlighted}",
            rail(),
            number
                .to_string()
                .truecolor(palette().muted.r, palette().muted.g, palette().muted.b),
            paint(RAIL_GLYPH, palette().muted)
        )
    } else {
        format!("  | {number:>4} | {line}")
    }
}

#[cfg(any(feature = "arch", test))]
pub(crate) fn kv(key: &str, value: &str) -> String {
    if crate::cli::style::colors_enabled() {
        format!(
            "  {}  {:<8}  {value}",
            rail(),
            key.truecolor(palette().muted.r, palette().muted.g, palette().muted.b)
        )
    } else {
        format!("  |  {key:<8}  {value}")
    }
}

#[cfg(any(feature = "arch", test))]
pub(crate) fn rail_line(body: &str) -> String {
    format!("  {}  {body}", rail())
}

#[cfg(any(feature = "arch", test))]
pub(crate) fn truncate_chars(line: &str, max: usize) -> String {
    let mut chars = line.chars();
    let taken: String = chars.by_ref().take(max).collect();
    if chars.next().is_none() {
        taken
    } else {
        format!(
            "{}…",
            taken
                .chars()
                .take(max.saturating_sub(1))
                .collect::<String>()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn parse_hex_accepts_full_and_short_forms() {
        assert_eq!(
            parse_hex("#7aa2f7"),
            Some(Rgb {
                r: 0x7a,
                g: 0xa2,
                b: 0xf7
            })
        );
        assert_eq!(
            parse_hex("f00"),
            Some(Rgb {
                r: 0xff,
                g: 0x00,
                b: 0x00
            })
        );
        assert_eq!(parse_hex("not-a-color"), None);
    }

    #[test]
    fn palette_reads_omarchy_colors_toml() {
        let parsed = Palette::parse_toml(
            "mode = \"dark\"\naccent = \"#89b4fa\"\nmuted = \"#585b70\"\ncyan = \"#94e2d5\"\nmagenta = \"#f5c2e7\"\ngreen = \"#a6e3a1\"\nyellow = \"#f9e2af\"\nred = \"#f38ba8\"\nblue = \"#89b4fa\"\n",
        )
        .expect("valid theme");
        assert_eq!(parsed.accent, parse_hex("#89b4fa").unwrap());
        assert_eq!(parsed.muted, parse_hex("#585b70").unwrap());
    }

    #[test]
    fn palette_tolerates_partial_toml() {
        let parsed = Palette::parse_toml("accent = \"#ff0000\"\n").expect("partial");
        assert_eq!(parsed.accent, parse_hex("#ff0000").unwrap());
        assert_eq!(parsed.cyan, Palette::fallback().cyan);
    }

    #[test]
    fn percent_encode_escapes_spaces() {
        assert_eq!(percent_encode_path("/tmp/a b"), "/tmp/a%20b");
    }

    #[test]
    fn kitty_bar_is_a_single_graphics_frame() {
        let encoded = kitty_rgb_bar(&[[255, 0, 0], [0, 255, 0]]);
        assert!(encoded.starts_with("\u{1b}_G"));
        assert!(encoded.contains("f=24"));
        assert!(encoded.contains("s=2"));
        assert!(encoded.ends_with("\u{1b}\\"));
    }

    #[test]
    #[serial]
    fn digest_stripe_is_plain_when_colors_are_off() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            let stripe = digest_stripe("abcdef0123456789");
            assert_eq!(stripe, "=".repeat(STRIPE_CELLS));
            assert!(!stripe.contains('\u{1b}'));
        });
    }

    #[test]
    #[serial]
    fn preview_chrome_is_plain_when_colors_are_off() {
        temp_env::with_var("NO_COLOR", Some("1"), || {
            assert_eq!(
                osc8_file(Path::new("/tmp/preview file"), "PKGBUILD"),
                "PKGBUILD"
            );
            assert_eq!(
                snippet_line(12, "source=('archive.tar.gz')"),
                "  |   12 | source=('archive.tar.gz')"
            );
            assert_eq!(kv("package", "example"), "  |  package   example");
            assert_eq!(
                rail_line("review before building"),
                "  |  review before building"
            );
        });
    }

    #[test]
    fn preview_truncation_preserves_unicode_and_character_limit() {
        assert_eq!(truncate_chars("αβγ", 3), "αβγ");
        assert_eq!(truncate_chars("αβγδ", 3), "αβ…");
        assert_eq!(truncate_chars("αβ", 1), "…");
        assert_eq!(truncate_chars("", 0), "");
    }

    #[test]
    #[serial]
    fn highlight_marks_source_and_comments() {
        temp_env::with_vars(
            [("NO_COLOR", None::<&str>), ("OMG_COLORS", Some("always"))],
            || {
                let source = highlight_pkgbuild_line("source=(\"https://example.test/a.tar.gz\")");
                assert!(source.contains("\u{1b}["), "{source}");
                let comment = highlight_pkgbuild_line("# Maintainer: x");
                assert!(comment.contains("\u{1b}["), "{comment}");
            },
        );
    }

    #[test]
    #[serial]
    fn osc8_http_rejects_non_http() {
        temp_env::with_vars(
            [("NO_COLOR", None::<&str>), ("OMG_COLORS", Some("always"))],
            || {
                assert_eq!(osc8_http("javascript:alert(1)", "x"), "x");
                let linked = osc8_http("https://example.test/pkg", "pkg");
                if std::io::stdout().is_terminal() {
                    assert!(linked.contains("https://example.test/pkg"), "{linked}");
                    assert!(linked.contains("\u{1b}]8;;"), "{linked}");
                } else {
                    assert_eq!(linked, "pkg");
                }
            },
        );
    }
}
