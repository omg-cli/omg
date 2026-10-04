"""Run real shell migration/removal against disposable POSIX filesystems."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ShellBackupSafety(unittest.TestCase):
    def check_backup(self, action, shape, platform="native"):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            install = home / "bin with ' quote"
            install.mkdir()
            rc = home / ".bashrc"
            original = f'# keep me\nexport PATH="{install}:$PATH"\neval "$(omg hook bash)"\n'
            rc.write_text(original)
            rc.chmod(0o640)
            target = home / "unrelated"
            target.write_text("untouched\n")
            backup = home / ".bashrc.omg-backup"
            if shape == "symlink":
                backup.symlink_to(target)
            elif shape == "dangling":
                backup.symlink_to(home / "absent")
            elif shape == "hardlink":
                os.link(target, backup)
            elif shape in {"regular", "copy_failure", "rename_failure"}:
                backup.write_text("previous backup\n")
            elif shape == "directory":
                backup.mkdir()
                (backup / ".bashrc").write_text("untouched child\n")
            injection = ""
            if shape.startswith("race_"):
                injection = '''
cp() {
  if [[ "${raced:-0}" == 0 ]]; then
    raced=1
    case "$SHAPE" in
      race_symlink) ln -s "$HOME/unrelated" "$HOME/.bashrc.omg-backup" ;;
      race_hardlink) ln "$HOME/unrelated" "$HOME/.bashrc.omg-backup" ;;
      race_directory) mkdir "$HOME/.bashrc.omg-backup"; printf 'untouched child\\n' > "$HOME/.bashrc.omg-backup/.bashrc" ;;
    esac
  fi
  command cp "$@"
}
'''
            elif shape == "copy_failure":
                injection = "cp() { return 42; }\n"
            elif shape == "rename_failure":
                # Remove the staged source after a successful copy. Both GNU
                # mv and Darwin's absolute Perl rename must really fail.
                injection = '''
cp() {
  command cp "$@" || return
  case "$3" in
    "$HOME"/*.omg-backup-stage.*/backup) rm "$3" ;;
    *) return 98 ;;
  esac
}
'''
            if platform == "darwin":
                injection = "uname() { printf 'Darwin\\n'; }\n" + injection
            # Complete the file before sourcing it: the hosted macOS fixture
            # did not load functions through process substitution.
            functions = home / "installer-functions.sh"
            functions.write_text("".join((ROOT / "install.sh").read_text().splitlines(keepends=True)[:-1]))
            script = ('source "$INSTALLER"\n'
                      'declare -F setup_shell uninstall_omg >/dev/null || exit 99\n'
                      + injection + action)
            result = subprocess.run(["bash", "-c", script], text=True,
                                    capture_output=True, timeout=10,
                                    env={**os.environ, "HOME": directory,
                                         "SHELL": "/bin/bash", "INSTALL_DIR": str(install),
                                         "INSTALLER": str(functions), "SHAPE": shape})
            self.assertEqual(target.read_text(), "untouched\n", result.stdout + result.stderr)
            failure = shape in {"symlink", "dangling", "directory", "race_directory",
                                "copy_failure", "rename_failure"}
            if failure:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(rc.read_text(), original)
                if shape in {"copy_failure", "rename_failure"}:
                    self.assertEqual(backup.read_text(), "previous backup\n")
                    diagnostic = "Failed to copy shell backup" if shape == "copy_failure" else "Failed to publish shell backup"
                    self.assertIn(diagnostic, result.stdout + result.stderr)
                if shape in {"directory", "race_directory"}:
                    self.assertTrue(backup.is_dir())
                    self.assertEqual((backup / ".bashrc").read_text(), "untouched child\n")
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(backup.is_symlink())
                self.assertEqual(backup.read_text(), original)
                self.assertNotEqual(backup.stat().st_ino, target.stat().st_ino)
                if action == "setup_shell":
                    self.assertNotIn(f'export PATH="{install}:$PATH"', rc.read_text())
                    environment = subprocess.run(
                        ["bash", "-c", 'source "$HOME/.bashrc"; printf "%s" "$PATH"'],
                        text=True, capture_output=True,
                        env={**os.environ, "HOME": directory}, timeout=10)
                    self.assertTrue(environment.stdout.startswith(str(install) + ":"))
                else:
                    self.assertEqual(rc.read_text(), "# keep me\n")
            self.assertEqual(rc.stat().st_mode & 0o777, 0o640)
            self.assertEqual(list(home.glob("*.omg-backup-stage.*")), [])

    def test_migration_backup_safety(self):
        for shape in ("absent", "regular", "symlink", "dangling", "hardlink", "directory",
                      "race_symlink", "race_hardlink", "race_directory", "copy_failure", "rename_failure"):
            with self.subTest(shape=shape):
                self.check_backup("setup_shell", shape)

    def test_uninstall_backup_safety(self):
        for shape in ("absent", "regular", "symlink", "dangling", "hardlink", "directory",
                      "race_symlink", "race_hardlink", "race_directory", "copy_failure", "rename_failure"):
            with self.subTest(shape=shape):
                self.check_backup("uninstall_omg", shape)

    def test_darwin_backup_safety(self):
        for action in ("setup_shell", "uninstall_omg"):
            for shape in ("absent", "regular", "symlink", "dangling", "hardlink", "directory",
                          "race_symlink", "race_hardlink", "race_directory", "copy_failure", "rename_failure"):
                with self.subTest(action=action, shape=shape):
                    self.check_backup(action, shape, "darwin")


if __name__ == "__main__":
    unittest.main()
