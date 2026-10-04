//! Persistent overrides must resolve independently of an unprivileged caller's CWD.

use std::path::PathBuf;
use std::process::Command;

use omg_lib::core::paths;

const OVERRIDES: [&str; 4] = [
    "OMG_DATA_DIR",
    "OMG_DAEMON_DATA_DIR",
    "OMG_CACHE_DIR",
    "OMG_PACMAN_ROOT",
];

#[test]
fn persistent_overrides_are_cwd_independent() {
    #[cfg(unix)]
    if omg_lib::core::is_root() {
        use std::os::unix::process::CommandExt;

        // Container suites run as root; exercise the real unprivileged branch.
        let user = nix::unistd::User::from_name("nobody").unwrap().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "persistent_overrides_are_cwd_independent",
                "--nocapture",
            ])
            .uid(user.uid.as_raw())
            .gid(user.gid.as_raw())
            .current_dir("/")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    if let Ok(case) = std::env::var("OMG_PATH_REGRESSION_CASE") {
        assert!(!omg_lib::core::is_root(), "run this regression as non-root");
        let base = PathBuf::from(std::env::var_os("OMG_PATH_REGRESSION_BASE").unwrap());
        let name = std::env::var("OMG_PATH_REGRESSION_NAME").unwrap();
        let (actual, default) = match name.as_str() {
            "OMG_DATA_DIR" => (paths::data_dir(), base.join("xdg-data/omg")),
            "OMG_DAEMON_DATA_DIR" => (paths::daemon_data_dir(), base.join("xdg-data/omg")),
            "OMG_CACHE_DIR" => (paths::cache_dir(), base.join("xdg-cache/omg")),
            "OMG_PACMAN_ROOT" => (paths::pacman_root(), PathBuf::from("/")),
            _ => panic!("unknown override {name}"),
        };
        let expected = if case == "absolute" {
            base.join("override")
        } else {
            default
        };
        assert_eq!(actual, expected, "{name}: {case}");
        assert!(actual.is_absolute(), "{name}: {case}");
        #[cfg(feature = "arch")]
        if name == "OMG_PACMAN_ROOT" && case == "relative" {
            let error = paths::pacman_root_result().unwrap_err().to_string();
            assert!(error.contains("OMG_PACMAN_ROOT must be an absolute path"));
        }
        return;
    }

    let fixture = tempfile::tempdir().unwrap();
    let mut failures = Vec::new();
    for cwd in ["a", "b"] {
        let cwd = fixture.path().join(cwd);
        std::fs::create_dir(&cwd).unwrap();
        for name in OVERRIDES {
            for case in ["relative", "absolute", "empty", "unset"] {
                let mut child = Command::new(std::env::current_exe().unwrap());
                child
                    .args([
                        "--exact",
                        "persistent_overrides_are_cwd_independent",
                        "--nocapture",
                    ])
                    .current_dir(&cwd)
                    .env("OMG_PATH_REGRESSION_CASE", case)
                    .env("OMG_PATH_REGRESSION_NAME", name)
                    .env("OMG_PATH_REGRESSION_BASE", fixture.path())
                    .env("XDG_DATA_HOME", fixture.path().join("xdg-data"))
                    .env("XDG_CACHE_HOME", fixture.path().join("xdg-cache"));
                for override_name in OVERRIDES {
                    child.env_remove(override_name);
                }
                match case {
                    "relative" => {
                        child.env(name, "rel/state");
                    }
                    "absolute" => {
                        child.env(name, fixture.path().join("override"));
                    }
                    "empty" => {
                        child.env(name, "");
                    }
                    "unset" => {}
                    _ => unreachable!(),
                }
                let output = child.output().unwrap();
                if !output.status.success() {
                    failures.push(format!(
                        "{name} {case} from {}: {}{}",
                        cwd.display(),
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
