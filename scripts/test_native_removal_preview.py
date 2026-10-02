"""Exercise the actual generic preview against a disposable native-plan fixture."""

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class NativeRemovalPreviewTests(unittest.TestCase):
    def test_preview_includes_reverse_dependencies_from_native_plan(self):
        output = self.run_preview("dnf")
        self.assertIn("library 1.0", output)
        self.assertIn("application 2.0", output)
        self.assertIn("confirmation-count=2", output)

    def test_adapter_without_native_plan_retains_requested_metadata_preview(self):
        output = self.run_preview("homebrew")
        self.assertIn("library 1.0", output)
        self.assertNotIn("application 2.0", output)
        self.assertIn("Requested Removal Targets", output)
        self.assertIn("confirmation-count=1", output)

    def test_normal_removal_confirms_complete_native_set_before_execution(self):
        output = self.run_preview("dnf", normal=True)
        self.assertIn("confirm-count=2", output)
        self.assertIn("application 2.0", output)
        self.assertNotIn("executed", output)
        self.assertLess(output.index("application 2.0"), output.index("confirm-count=2"))

    def run_preview(self, backend, normal=False):
        source = r'''
extern crate anyhow;
mod core { pub mod security {
    pub fn validate_package_names(_: &[String]) -> anyhow::Result<()> { Ok(()) }
    pub fn validate_package_name(_: &str) -> anyhow::Result<()> { Ok(()) }
} pub mod paths { pub fn test_mode() -> bool { false } } }
mod package_managers {
    pub struct Package { pub name: String, pub version: String }
    pub mod types { pub type RemovalPackage = super::Package; }
    pub struct Manager;
    pub fn get_package_manager() -> anyhow::Result<Manager> { Ok(Manager) }
    impl Manager {
        pub fn name(&self) -> &'static str { "__BACKEND__" }
        pub async fn list_installed(&self) -> anyhow::Result<Vec<Package>> {
            Ok(vec![Package { name: "library".into(), version: "1.0".into() },
                    Package { name: "application".into(), version: "2.0".into() }])
        }
        pub async fn removal_plan(&self, _: &[String]) -> anyhow::Result<Vec<Package>> {
            if self.name() == "homebrew" { anyhow::bail!("no native simulation"); }
            self.list_installed().await
        }
    }
}
mod cli {
    pub mod style {
        pub fn info(s: &str) -> &str { s }
        pub fn error(s: &str) -> &str { s }
        pub fn package(s: &str) -> &str { s }
        pub fn version(s: &str) -> &str { s }
    }
    pub mod ui { pub fn print_spacer() {} pub fn print_dry_run_footer() {} }
    pub mod modern_ui {
        pub fn print_phase_header(_: &str, title: &str, _: &str) { println!("{title}"); }
        pub fn print_warning(message: &str) { println!("{message}"); }
    }
    pub mod remove { include!("__SOURCE__"); }
    pub async fn confirmation_count(requested: &[String]) -> anyhow::Result<usize> {
        remove::confirmation_count(requested).await
    }
    pub mod packages {
        macro_rules! dispatch_backend {
            (debian: $debian:block, arch: $arch:block, generic: $generic:block $(,)?) => { $generic };
        }
        pub(crate) use dispatch_backend;
        pub mod common {
            pub async fn confirm_package_mutation(_: &str, count: usize, _: bool) -> anyhow::Result<bool> {
                println!("confirm-count={count}"); Ok(false)
            }
            pub async fn remove_via_service(_: &[String]) -> anyhow::Result<()> { panic!("executed"); }
            pub async fn remove_with_manager(_: &[String], _: crate::package_managers::Manager) -> anyhow::Result<()> {
                panic!("executed");
            }
        }
        #[path = "__OUTER_SOURCE__"] pub mod remove;
    }
}
fn main() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let requested = vec!["library".into()];
    let mut future = Box::pin(__RUN__);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result.unwrap(),
        Poll::Pending => panic!("fixture unexpectedly blocked"),
    }
    let mut confirmation = Box::pin(cli::confirmation_count(&requested));
    match confirmation.as_mut().poll(&mut context) {
        Poll::Ready(result) => println!("confirmation-count={}", result.unwrap()),
        Poll::Pending => panic!("fixture unexpectedly blocked"),
    }
}
'''.replace("__SOURCE__", str(ROOT / "src/cli/packages/remove/generic.rs"))
        source = source.replace("__BACKEND__", backend).replace("__RUN__", (
            "cli::packages::remove::remove(&requested, false, false, false)" if normal
            else "cli::remove::remove_dry_run(&requested)"))
        with tempfile.TemporaryDirectory(prefix="omg-removal-proof-") as directory:
            path = pathlib.Path(directory)
            removal = path / "remove"
            removal.mkdir()
            (removal / "mod.rs").write_text((ROOT / "src/cli/packages/remove.rs").read_text())
            (removal / "generic.rs").write_text((ROOT / "src/cli/packages/remove/generic.rs").read_text())
            source = source.replace("__OUTER_SOURCE__", str(removal / "mod.rs"))
            # This fixture substitutes the manager and error formatting only.
            # Compile the real preview/confirmation functions before Cargo has
            # built any dependencies, as required by the hosted Quick Gate.
            error_shim = path / "anyhow.rs"
            error_shim.write_text(r'''
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
#[macro_export] macro_rules! anyhow {
    ($($arg:tt)*) => { $crate::Error::from(format!($($arg)*)) };
}
#[macro_export] macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::anyhow!($($arg)*)) };
}
#[macro_export] macro_rules! ensure {
    ($condition:expr, $($arg:tt)*) => {
        if !$condition { $crate::bail!($($arg)*); }
    };
}
''')
            anyhow = path / "libanyhow.rlib"
            shim = subprocess.run(["rustc", "--edition=2024", "--crate-name", "anyhow",
                                   "--crate-type", "rlib", str(error_shim), "-o", str(anyhow)],
                                  capture_output=True, text=True)
            self.assertEqual(shim.returncode, 0, shim.stderr)
            (path / "proof.rs").write_text(source)
            compiled = subprocess.run(["rustc", "--edition=2024", str(path / "proof.rs"),
                            "--extern", f"anyhow={anyhow}",
                            "-o", str(path / "proof")], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            output = subprocess.check_output([str(path / "proof")], text=True)
        return output


if __name__ == "__main__":
    unittest.main()
