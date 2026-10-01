//! Distro detection helpers
//!
//! Supports detection of:
//! - Arch Linux and derivatives (Manjaro, `EndeavourOS`, etc.)
//! - Debian and derivatives (Ubuntu, Linux Mint, `Pop!_OS`, etc.)
//! - Fedora and derivatives (RHEL, `CentOS`, Rocky, Alma, etc.)
//! - macOS (via `uname`)
//!
//! Windows Subsystem for Linux is detected through its Linux distribution.
//! Native Windows is not supported.

use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;

/// Supported operating systems and distributions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    /// Arch Linux and derivatives (`pacman`/ALPM)
    Arch,
    /// Debian `GNU/Linux`
    Debian,
    /// Ubuntu
    Ubuntu,
    /// Fedora, RHEL, `CentOS`, Rocky, Alma (`DNF`/RPM)
    Fedora,
    /// macOS (`Homebrew`)
    MacOS,
    /// Unknown or unsupported
    Unknown,
}

/// Detect the current operating system/distribution
#[must_use]
pub fn detect_distro() -> Distro {
    static DISTRO: OnceLock<Distro> = OnceLock::new();
    *DISTRO.get_or_init(|| {
        // Test mode override
        if crate::core::paths::test_mode()
            && let Ok(overridden) = std::env::var("OMG_TEST_DISTRO")
        {
            return match overridden.to_lowercase().as_str() {
                "arch" => Distro::Arch,
                "debian" => Distro::Debian,
                "ubuntu" => Distro::Ubuntu,
                "fedora" | "rhel" | "centos" | "rocky" | "alma" => Distro::Fedora,
                "macos" | "darwin" => Distro::MacOS,
                _ => Distro::Unknown,
            };
        }

        // macOS detection (compile-time)
        #[cfg(target_os = "macos")]
        {
            return Distro::MacOS;
        }

        // Linux detection via /etc/os-release
        #[cfg(target_os = "linux")]
        {
            let data = fs::read_to_string("/etc/os-release").ok();
            let map = data.as_deref().map(parse_os_release).unwrap_or_default();

            let id = map.get("ID").map(String::as_str).unwrap_or_default();
            let id_like = map.get("ID_LIKE").map(String::as_str).unwrap_or_default();

            classify(id, id_like)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Distro::Unknown
        }
    })
}

/// Returns true if running on Debian or Ubuntu
#[must_use]
pub fn is_debian_like() -> bool {
    matches!(detect_distro(), Distro::Debian | Distro::Ubuntu)
}

/// Check if we should use Debian backend based on current distro and features
#[must_use]
pub fn use_debian_backend() -> bool {
    #[cfg(feature = "debian")]
    {
        is_debian_like()
    }

    #[cfg(not(feature = "debian"))]
    {
        false
    }
}

/// Classify a distribution from its os-release `ID`/`ID_LIKE` values.
///
/// Order matters:
/// 1. Arch family (pacman/ALPM backend).
/// 2. Fedora/RHEL family (DNF backend).
/// 3. Ubuntu family — including derivatives such as Pop!_OS, KDE neon, and
///    elementary that declare `ubuntu` in `ID_LIKE`. They must classify as
///    [`Distro::Ubuntu`] so consumers like self-update pick Ubuntu-built
///    artifacts; package-manager selection treats Ubuntu and Debian alike.
/// 4. Debian family (apt backend). Pure-Debian-claimed derivatives such as
///    Linux Mint (`ID_LIKE="debian"`) land here; they still get the apt
///    backend.
fn classify(id: &str, id_like: &str) -> Distro {
    // Arch Linux and derivatives
    if is_like(id, id_like, "arch") {
        return Distro::Arch;
    }

    // Fedora and RHEL-family
    if id == "fedora"
        || is_like(id, id_like, "fedora")
        || is_like(id, id_like, "rhel")
        || id == "rhel"
        || id == "centos"
        || id == "rocky"
        || id == "almalinux"
    {
        return Distro::Fedora;
    }

    // Ubuntu and Ubuntu-family derivatives (checked before debian since every
    // Ubuntu derivative is also debian-like)
    if id == "ubuntu" || is_like(id, id_like, "ubuntu") {
        return Distro::Ubuntu;
    }

    // Debian and other derivatives
    if id == "debian" || is_like(id, id_like, "debian") {
        return Distro::Debian;
    }

    Distro::Unknown
}

fn is_like(id: &str, id_like: &str, needle: &str) -> bool {
    id == needle
        || id_like
            .split_whitespace()
            .any(|value| value.trim() == needle)
}

fn parse_os_release(contents: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && let Some(value) = parse_os_release_value(value.trim())
        {
            map.insert(key.to_string(), value);
        }
    }
    map
}

/// Decode an assignment value, never execute shell syntax or expand variables.
fn parse_os_release_value(value: &str) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    if let Some(inner) = value.strip_prefix('\'') {
        let inner = inner.strip_suffix('\'')?;
        return (!inner.contains('\'')).then(|| inner.to_string());
    }
    let (inner, quoted) = if let Some(inner) = value.strip_prefix('"') {
        (inner.strip_suffix('"')?, true)
    } else {
        (value, false)
    };
    let mut decoded = String::new();
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        match character {
            '\\' => {
                let escaped = chars.next()?;
                if quoted && !matches!(escaped, '$' | '`' | '"' | '\\') {
                    decoded.push('\\');
                }
                decoded.push(escaped);
            }
            '"' => return None,
            '\'' | ';' | '$' | '`' if !quoted => return None,
            character if !quoted && character.is_whitespace() => return None,
            character => decoded.push(character),
        }
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_family_including_derivatives() {
        assert_eq!(classify("arch", ""), Distro::Arch);
        assert_eq!(classify("manjaro", "arch"), Distro::Arch);
        assert_eq!(classify("endeavouros", "arch"), Distro::Arch);
        assert_eq!(classify("archarm", "arch"), Distro::Arch);
        assert_eq!(classify("cachyos", "arch"), Distro::Arch);
    }

    #[test]
    fn fedora_family() {
        assert_eq!(classify("fedora", ""), Distro::Fedora);
        assert_eq!(classify("rhel", "fedora"), Distro::Fedora);
        assert_eq!(classify("centos", "rhel fedora"), Distro::Fedora);
        assert_eq!(classify("rocky", "rhel fedora"), Distro::Fedora);
        assert_eq!(classify("ol", "fedora rhel centos"), Distro::Fedora);
        assert_eq!(classify("amzn", "centos rhel fedora"), Distro::Fedora);
    }

    #[test]
    fn ubuntu_and_ubuntu_family_derivatives_classify_as_ubuntu() {
        assert_eq!(classify("ubuntu", "debian"), Distro::Ubuntu);
        // Pop!_OS declares ID_LIKE="ubuntu debian"
        assert_eq!(classify("pop", "ubuntu debian"), Distro::Ubuntu);
        // KDE neon
        assert_eq!(classify("neon", "ubuntu debian"), Distro::Ubuntu);
        // elementary OS
        assert_eq!(classify("elementary", "ubuntu debian"), Distro::Ubuntu);
        // Trisquel
        assert_eq!(classify("trisquel", "ubuntu"), Distro::Ubuntu);
    }

    #[test]
    fn debian_family() {
        assert_eq!(classify("debian", ""), Distro::Debian);
        // Linux Mint claims only "debian" in ID_LIKE; it still gets the apt
        // backend, so Debian classification is acceptable there.
        assert_eq!(classify("linuxmint", "debian"), Distro::Debian);
        assert_eq!(classify("kali", "debian"), Distro::Debian);
    }

    #[test]
    fn quoted_identifiers_and_id_like_classify_without_quote_artifacts() {
        for input in ["ID=fedora", "ID='fedora'", "ID=\"fedora\""] {
            let fields = parse_os_release(input);
            assert_eq!(fields["ID"], "fedora");
            assert_eq!(classify(&fields["ID"], ""), Distro::Fedora);
        }
        for value in ["'ubuntu debian'", "\"ubuntu debian\"", "ubuntu\\ debian"] {
            let fields = parse_os_release(&format!("ID=pop\nID_LIKE={value}"));
            assert_eq!(fields["ID_LIKE"], "ubuntu debian");
            assert_eq!(classify(&fields["ID"], &fields["ID_LIKE"]), Distro::Ubuntu);
        }
    }

    #[test]
    fn comments_blank_lines_and_later_valid_keys_are_preserved() {
        let fields =
            parse_os_release(" # comment\n\nID=arch\nID='fedora'\nNAME=\"Fédora Linux\"\nEMPTY=\n");
        assert_eq!(fields["ID"], "fedora");
        assert_eq!(fields["NAME"], "Fédora Linux");
        assert_eq!(fields["EMPTY"], "");
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn escapes_follow_quote_context_without_variable_expansion() {
        assert_eq!(
            parse_os_release_value(r#""a\"b\\c\$HOME\`command\`\q""#).as_deref(),
            Some("a\"b\\c$HOME`command`\\q")
        );
        assert_eq!(
            parse_os_release_value(r"'\$HOME `command`'").as_deref(),
            Some(r"\$HOME `command`")
        );
        assert_eq!(
            parse_os_release_value(r"ubuntu\ debian").as_deref(),
            Some("ubuntu debian")
        );
        assert_eq!(parse_os_release_value("\"$ID\"").as_deref(), Some("$ID"));
        assert_eq!(classify("$ID", ""), Distro::Unknown);
    }

    #[test]
    fn malformed_quotes_concatenation_and_dangling_escapes_are_rejected() {
        for value in [
            "'fedora",
            "fedora'",
            "\"fedora",
            "fedora\"",
            "'fedora''arch'",
            "\"fedora\"\"arch\"",
            "fedora\\",
            "\"fedora\\\"",
            "ubuntu debian",
            "$(command)",
            "`command`",
            "fedora;arch",
        ] {
            assert_eq!(parse_os_release_value(value), None, "{value:?}");
            assert!(parse_os_release(&format!("ID={value}")).is_empty());
        }
    }

    #[test]
    fn literal_quoted_special_characters_and_empty_values_are_retained() {
        for (input, expected) in [
            ("''", ""),
            ("\"\"", ""),
            ("'a;b=$HOME'", "a;b=$HOME"),
            ("\"it's Linux\"", "it's Linux"),
        ] {
            assert_eq!(parse_os_release_value(input).as_deref(), Some(expected));
        }
    }

    #[test]
    fn unknown_distributions_do_not_match_any_family() {
        assert_eq!(classify("alpine", ""), Distro::Unknown);
        assert_eq!(classify("opensuse-leap", "suse opensuse"), Distro::Unknown);
        assert_eq!(classify("", ""), Distro::Unknown);
    }
}
