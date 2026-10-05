//! Production detection regression without environment mutation in libtest.
use omg_lib::core::env::distro::{Distro, detect_distro};
use std::process::Command;

fn overridden_distro(mode: Option<&str>, distro: Option<&str>) -> Distro {
    // This harness-free child starts no threads, runtime, or native backend.
    // The helper restores env even on panic; its mutex alone would not make
    // arbitrary concurrent readers safe, so never run this under libtest.
    temp_env::with_vars(
        [("OMG_TEST_MODE", mode), ("OMG_TEST_DISTRO", distro)],
        detect_distro,
    )
}
fn transitions() {
    let native = detect_distro();
    let (override_name, expected) = if native == Distro::Debian {
        ("ubuntu", Distro::Ubuntu)
    } else {
        ("debian", Distro::Debian)
    };
    assert_eq!(
        overridden_distro(Some("1"), Some(override_name)),
        expected,
        "late activation after native cache"
    );
    assert_eq!(
        overridden_distro(Some("1"), Some("arch")),
        Distro::Arch,
        "changed override"
    );
    assert_eq!(
        overridden_distro(Some("TRUE"), Some("debian")),
        Distro::Debian,
        "truthy test mode"
    );
    assert_eq!(
        overridden_distro(Some("1"), None),
        Distro::Arch,
        "Doctor/mock unset default"
    );
    for mode in [None, Some("0"), Some("")] {
        assert_eq!(
            overridden_distro(mode, Some(override_name)),
            native,
            "disabled test mode {mode:?}"
        );
    }
}

fn override_first() {
    assert_eq!(detect_distro(), Distro::Debian, "fresh override");
    assert_eq!(
        overridden_distro(Some("1"), Some("ubuntu")),
        Distro::Ubuntu,
        "override before native init"
    );
    let native = overridden_distro(None, None);
    assert_eq!(overridden_distro(Some("1"), Some("debian")), Distro::Debian);
    assert_eq!(
        overridden_distro(None, None),
        native,
        "native cache survives override"
    );
}

fn aliases() {
    for (name, expected) in [
        ("arch", Distro::Arch),
        ("debian", Distro::Debian),
        ("ubuntu", Distro::Ubuntu),
        ("fedora", Distro::Fedora),
        ("rhel", Distro::Fedora),
        ("centos", Distro::Fedora),
        ("rocky", Distro::Fedora),
        ("alma", Distro::Fedora),
        ("macos", Distro::MacOS),
        ("darwin", Distro::MacOS),
        ("DeBiAn", Distro::Debian),
        ("nonsense", Distro::Unknown),
        ("", Distro::Unknown),
    ] {
        assert_eq!(
            overridden_distro(Some("1"), Some(name)),
            expected,
            "alias {name:?}"
        );
    }
}

fn release_guard() {
    let native = detect_distro();
    for mode in ["1", "true", "TRUE"] {
        for name in ["arch", "debian", "ubuntu", "fedora", "macos", "nonsense"] {
            assert_eq!(
                overridden_distro(Some(mode), Some(name)),
                native,
                "release ignores {mode}/{name}"
            );
        }
    }
}

fn main() {
    if let Some(scenario) = std::env::args().nth(1) {
        match scenario.as_str() {
            "transitions" => transitions(),
            "override-first" => override_first(),
            "aliases" => aliases(),
            "release" => release_guard(),
            _ => panic!("unknown scenario {scenario}"),
        }
        println!("PASS {scenario}");
        return;
    }

    let executable = std::env::current_exe().expect("test executable");
    let scenarios: &[&str] = if cfg!(debug_assertions) {
        &["transitions", "override-first", "aliases"]
    } else {
        &["release"]
    };
    for scenario in scenarios {
        let status = Command::new(&executable)
            .arg(scenario)
            .env_remove("OMG_TEST_MODE")
            .env_remove("OMG_TEST_DISTRO")
            .envs(if *scenario == "override-first" {
                vec![("OMG_TEST_MODE", "1"), ("OMG_TEST_DISTRO", "debian")]
            } else {
                Vec::new()
            })
            .status()
            .expect("isolated regression child");
        assert!(status.success(), "scenario {scenario}: {status}");
    }
}
