//! Doctor must refuse completed setup when real sudo authorization fails.
#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use nix::unistd::{Gid, Uid, chown};
use sha2::{Digest, Sha256};

fn executable_digest(path: &Path) -> [u8; 32] {
    let mut file = std::fs::File::open(path).expect("fixture executable");
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer).expect("fixture executable bytes");
        if read == 0 {
            return digest.finalize().into();
        }
        digest.update(&buffer[..read]);
    }
}

#[test]
fn doctor_turbo_refuses_completion_when_sudo_cannot_gain_privileges() {
    let fixture = tempfile::TempDir::new_in("/var/tmp").expect("private Doctor fixture");
    let original = Path::new(env!("CARGO_BIN_EXE_omg"));
    let binary = fixture.path().join("omg");
    let home = fixture.path().join("home");
    std::fs::copy(original, &binary).expect("private CLI copy");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .expect("ordinary executable permissions");
    std::fs::create_dir(&home).expect("private home");
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
        .expect("private home permissions");
    let digest = executable_digest(original);
    assert_eq!(executable_digest(&binary), digest);

    let timeout = omg_lib::core::privilege::root_controlled_program_path("timeout")
        .expect("trusted fixture deadline");
    let setpriv = omg_lib::core::privilege::root_controlled_program_path("setpriv")
        .expect("trusted no_new_privs launcher");
    let mut command = Command::new(timeout);
    command.args(["--kill-after=2s", "20s"]).arg(setpriv);
    if Uid::effective().is_root() {
        // Root-run distro tests must exercise the same ordinary-user refusal.
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755))
            .expect("ordinary fixture traversal");
        chown(
            &home,
            Some(Uid::from_raw(65534)),
            Some(Gid::from_raw(65534)),
        )
        .expect("own only the disposable home");
        command.args(["--reuid=65534", "--regid=65534", "--clear-groups"]);
    }
    // Process-local no_new_privs blocks sudo without changing machine policy.
    // https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html
    let output = command
        .arg("--no-new-privs")
        .arg(&binary)
        .args(["doctor", "--turbo"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("OMG_CONFIG_DIR", home.join("config"))
        .env("OMG_DISABLE_TELEMETRY", "1")
        .env("SENTRY_DSN", "")
        .env("LC_ALL", "C")
        .env("NO_COLOR", "1")
        .current_dir(&home)
        .stdin(Stdio::null())
        .output()
        .expect("real Doctor refusal");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code().expect("Doctor exit status");
    assert!(
        !matches!(code, 0 | 124 | 137)
            && stderr.contains("no new privileges")
            && stderr.contains("sudo credential validation failed")
            && !stdout.contains("No file capabilities remain (or none were set)")
            && !stdout.contains("No permanent privileges granted to any binary"),
        "Doctor must refuse authorization, not time out or report completion: {code}\n{stdout}\n{stderr}"
    );
    assert_eq!(executable_digest(&binary), digest, "private CLI changed");
    assert_eq!(executable_digest(original), digest, "original CLI changed");
}
