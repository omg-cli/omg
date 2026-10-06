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

fn harness_contract() {
    let executable = std::env::current_exe().expect("test executable");
    let listed = Command::new(&executable)
        .args(["--list", "--format", "terse"])
        .output()
        .expect("discovery child");
    assert!(listed.status.success(), "discovery: {listed:?}");
    let expected = if cfg!(debug_assertions) {
        "transitions: test\noverride-first: test\naliases: test\nharness-contract: test\n"
    } else {
        "release: test\nharness-contract: test\n"
    };
    assert_eq!(
        String::from_utf8(listed.stdout).expect("UTF-8 list"),
        expected
    );
    let ignored = Command::new(&executable)
        .args(["--list", "--format", "terse", "--ignored"])
        .output()
        .expect("ignored discovery child");
    assert!(ignored.status.success(), "ignored discovery: {ignored:?}");
    assert!(ignored.stdout.is_empty(), "no ignored scenarios");
    let scenario = if cfg!(debug_assertions) {
        "aliases"
    } else {
        "release"
    };
    let exact = Command::new(&executable)
        .args([scenario, "--nocapture", "--exact"])
        // Exact execution must still create a child with controlled initial env.
        .env("OMG_TEST_MODE", "1")
        .env("OMG_TEST_DISTRO", "nonsense")
        .output()
        .expect("exact execution child");
    assert!(exact.status.success(), "exact execution: {exact:?}");
    assert_eq!(
        String::from_utf8(exact.stdout).expect("UTF-8 result"),
        format!("PASS {scenario}\n")
    );
    let unmatched = Command::new(&executable)
        .args(["absent-scenario", "--nocapture", "--exact"])
        .output()
        .expect("unmatched exact child");
    assert!(unmatched.status.success(), "unmatched: {unmatched:?}");
    assert!(
        unmatched.stdout.is_empty(),
        "exact filter must not run other scenarios"
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    // Only this private entry executes assertions in a single-threaded child.
    // Nextest's exact execution must go through the parent setup below too.
    if std::env::args().nth(1).as_deref() == Some("--isolated-scenario") {
        args.next();
        let scenario = args.next().expect("isolated scenario name");
        assert!(args.next().is_none(), "unexpected isolated child argument");
        match scenario.as_str() {
            "transitions" => transitions(),
            "override-first" => override_first(),
            "aliases" => aliases(),
            "release" => release_guard(),
            "harness-contract" => harness_contract(),
            _ => panic!("unknown scenario {scenario}"),
        }
        println!("PASS {scenario}");
        return;
    }

    let scenarios: &[&str] = if cfg!(debug_assertions) {
        &[
            "transitions",
            "override-first",
            "aliases",
            "harness-contract",
        ]
    } else {
        &["release", "harness-contract"]
    };
    let mut list = false;
    let mut ignored = false;
    let mut exact = false;
    let mut filter = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list" => list = true,
            "--ignored" => ignored = true,
            "--exact" => exact = true,
            "--nocapture" => {} // Child output is always inherited.
            "--format" => assert_eq!(args.next().as_deref(), Some("terse")),
            _ if !arg.starts_with('-') && filter.is_none() => filter = Some(arg),
            _ => panic!("unsupported test argument {arg}"),
        }
    }
    let executable = std::env::current_exe().expect("test executable");
    for scenario in scenarios {
        if ignored
            || filter.as_deref().is_some_and(|filter| {
                if exact {
                    *scenario != filter
                } else {
                    !scenario.contains(filter)
                }
            })
        {
            continue;
        }
        if list {
            println!("{scenario}: test");
            continue;
        }
        let status = Command::new(&executable)
            .args(["--isolated-scenario", scenario])
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
