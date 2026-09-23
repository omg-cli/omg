"""Exercise the Arch AUR flag oracle, including false-green product mutants."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/qemu-aur-check.sh"
FIXTURE = ROOT / "scripts/qemu-aur-fixture.py"
FAKE = r'''#!/usr/bin/env python3
import json
import os
import ssl
import sys
import urllib.request

mode = os.environ["OMG_FAKE_MODE"]
args = sys.argv[1:]
no_aur = "--no-aur" in args
detailed = "--detailed" in args
if no_aur and mode != "leaky_no_aur":
    print("[]")
    sys.exit(0)
if mode == "skip_aur":
    print("[]")
    sys.exit(0)
context = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"https": os.environ["HTTPS_PROXY"]}),
    urllib.request.HTTPSHandler(context=context),
)
url = "https://aur.archlinux.org/rpc?v=5&type=search&arg=omgqemuaurprobe"
with opener.open(url, timeout=5) as response:
    source = json.load(response)["results"][0]
if no_aur:
    print("[]")
    sys.exit(0)
result = {
    "name": source["Name"], "version": source["Version"],
    "description": source["Description"], "source": "AUR",
}
if detailed and mode != "ignore_detailed":
    result.update(votes=source["NumVotes"], popularity=source["Popularity"],
                  maintainer=source["Maintainer"], out_of_date=True)
print(json.dumps([result]))
'''


class AurContractTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and Path("/etc/arch-release").exists(),
                         "full oracle needs an Arch Linux guest or WSL distro")
    def test_fixture_rejects_no_aur_leak_and_missing_detailed_metadata(self):
        for mode, expected in (
            ("good", None),
            ("leaky_no_aur", "--no-aur made an AUR connection"),
            ("ignore_detailed", "--detailed did not expose fixture AUR metadata"),
            ("skip_aur", "--detailed did not expose fixture AUR metadata"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                evidence = home / "evidence"
                evidence.mkdir()
                fake = home / "omg"
                fake.write_text(FAKE, encoding="utf-8")
                fake.chmod(0o755)
                preexec = None
                if os.geteuid() == 0:
                    for path in (home, evidence):
                        os.chown(path, 65534, 65534)

                    def drop_privileges():
                        os.setgroups([])
                        os.setgid(65534)
                        os.setuid(65534)

                    preexec = drop_privileges
                result = subprocess.run(
                    ["bash", str(CHECK), str(fake), str(evidence)],
                    env=dict(os.environ, HOME=str(home), OMG_FAKE_MODE=mode),
                    preexec_fn=preexec, capture_output=True, text=True,
                    timeout=90, check=False,
                )
                receipt = evidence / "aur-search-flags.json"
                if expected is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(receipt.is_file())
                    self.assertTrue(json.loads(receipt.read_text())["no_aur_suppressed"])
                    events = [json.loads(line) for line in
                              (evidence / "aur-fixture-events.jsonl").read_text().splitlines()]
                    self.assertEqual([entry["event"] for entry in events],
                                     ["connect", "request", "connect", "request"])
                else:
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(expected, result.stderr)
                    self.assertFalse(receipt.exists())

    def test_qemu_copies_fixture_and_requires_arch_receipt(self):
        runner = (ROOT / "scripts/benchmark-qemu.sh").read_text(encoding="utf-8")
        exporter = (ROOT / "scripts/export-qemu-evidence.py").read_text(encoding="utf-8")
        self.assertIn('cp "$here/qemu-aur-check.sh" "$here/qemu-aur-fixture.py" "$work/"', runner)
        self.assertIn('bash "$HOME/qemu-aur-check.sh" "$bin" "$HOME/evidence"', runner)
        self.assertIn('aur_receipt="$work/guest/evidence/aur-search-flags.json"', runner)
        for filename in ("aur-search-flags.json", "aur-fixture-events.jsonl",
                         "aur-detailed.json", "aur-no-aur.json", "aur-basic.json"):
            self.assertIn(f'"{filename}"', exporter)
        self.assertTrue(FIXTURE.is_file())


if __name__ == "__main__":
    unittest.main()
