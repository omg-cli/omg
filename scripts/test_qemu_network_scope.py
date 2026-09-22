import json
import errno
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NetworkScopeTests(unittest.TestCase):
    def test_workflow_requires_namespace_isolation(self):
        workflow = (ROOT / ".github/workflows/qemu-matrix.yml").read_text() + (ROOT / ".github/workflows/qemu-lane.yml").read_text()
        self.assertEqual(workflow.count("--inventory-isolate-hermetic"), 2)
        runner = (ROOT / "scripts/qemu-inventory.sh").read_text()
        self.assertIn('--isolate-hermetic) isolate_hermetic=true', runner)

    @unittest.skipIf(os.name == "nt", "Linux network namespaces are verified in hosted CI")
    def test_actual_remote_wrapper_has_no_external_interface_and_preserves_user(self):
        self.check_remote_wrapper(as_root=False)

    @unittest.skipIf(os.name == "nt", "Linux network namespaces are verified in hosted CI")
    def test_root_remote_wrapper_also_drops_all_capabilities(self):
        self.check_remote_wrapper(as_root=True)

    @unittest.skipIf(os.name == "nt", "Linux network namespaces are verified in hosted CI")
    def test_cached_upgrade_wrapper_retains_root_inside_offline_namespace(self):
        source = (ROOT / "scripts/qemu-inventory.sh").read_text()
        line = next(
            line.strip()
            for line in source.splitlines()
            if line.strip().startswith('remote="sudo -n unshare') and 'USER=root' in line
        )
        probe = """
import json, os, socket, subprocess
connections=[]
for family,address in [(socket.AF_INET,('192.0.2.1',443)),(socket.AF_INET6,('2001:db8::1',443))]:
    with socket.socket(family,socket.SOCK_STREAM) as client:
        client.settimeout(1); connections.append(client.connect_ex(address))
print(json.dumps(dict(uid=os.getuid(), routes4=json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all'])), routes6=json.loads(subprocess.check_output(['ip','-j','-6','route','show','table','all'])), connections=connections)))
"""
        import shlex
        command = shlex.join([sys.executable, "-c", probe])
        script = 'remote=' + shlex.quote(command) + '\n' + line + '\nbash -c "$remote"'
        result = subprocess.run(
            ["sudo", "-n", "bash", "-euo", "pipefail", "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["uid"], 0)
        self.assertEqual(receipt["routes4"], [])
        self.assertEqual(receipt["routes6"], [])
        self.assertEqual(receipt["connections"][0], errno.ENETUNREACH)
        self.assertIn(receipt["connections"][1], (errno.ENETUNREACH, errno.EADDRNOTAVAIL))

    def check_remote_wrapper(self, *, as_root):
        source = (ROOT / "scripts/qemu-inventory.sh").read_text()
        line = next(
            line.strip()
            for line in source.splitlines()
            if line.strip().startswith('remote="sudo -n unshare') and 'setpriv' in line
        )
        probe = """
import errno, json, os, socket, subprocess
from pathlib import Path
connections = []
for family, address in [(socket.AF_INET, ('192.0.2.1', 443)),
                        (socket.AF_INET6, ('2001:db8::1', 443))]:
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        connections.append(client.connect_ex(address))
print(json.dumps(dict(
    uid=os.getuid(), gid=os.getgid(),
    links=json.loads(subprocess.check_output(['ip', '-j', 'link'])),
    routes4=json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])),
    routes6=json.loads(subprocess.check_output(['ip', '-j', '-6', 'route', 'show', 'table', 'all'])),
    connections=connections, status=Path('/proc/self/status').read_text())))
"""
        # Build the same quoted inner command that the inventory wraps.
        import shlex
        command = shlex.join([sys.executable, "-c", probe])
        script = 'remote=' + shlex.quote(command) + '\nssh_user=' + shlex.quote(str(0 if as_root else os.getuid())) + '\n' + line + '\nbash -c "$remote"'
        invocation = ["bash", "-euo", "pipefail", "-c", script]
        if as_root:
            invocation = ["sudo", "-n", *invocation]
        result = subprocess.run(invocation, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["uid"], 0 if as_root else os.getuid())
        self.assertEqual(receipt["gid"], 0 if as_root else os.getgid())
        # Kernels may create down fallback tunnels in every new namespace.
        # Verify isolation rather than assuming a particular module inventory.
        self.assertIn("lo", [link["ifname"] for link in receipt["links"]])
        for link in receipt["links"]:
            self.assertNotIn("UP", link["flags"], link)
        self.assertEqual(receipt["routes4"], [])
        self.assertEqual(receipt["routes6"], [])
        import errno
        self.assertEqual(receipt["connections"][0], errno.ENETUNREACH)
        # IPv6 may reject the absent source address before route lookup.
        self.assertIn(receipt["connections"][1], (errno.ENETUNREACH, errno.EADDRNOTAVAIL))
        status = dict(line.split(':', 1) for line in receipt["status"].splitlines() if ':' in line)
        self.assertEqual(status["NoNewPrivs"].strip(), "1")
        for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertEqual(int(status[capability_set].strip(), 16), 0, capability_set)


if __name__ == "__main__":
    unittest.main()
