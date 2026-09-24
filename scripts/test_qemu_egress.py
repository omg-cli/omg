import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("egress", Path(__file__).with_name("qemu-controller-egress.py"))
EGRESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EGRESS)
NAME = "omg-qemu-run-ABC123"


class EgressTests(unittest.TestCase):
    def test_rules_reject_private_and_runner_destinations_before_allowing_web(self):
        rules = list(EGRESS.rules("172.17.0.2"))
        web = rules.index(["-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "RETURN"])
        self.assertEqual(rules[0], ["!", "-s", "172.17.0.2", "-j", "RETURN"])
        self.assertLess(rules.index(["-m", "addrtype", "--dst-type", "LOCAL", "-j", "REJECT"]), web)
        for network in EGRESS.PRIVATE:
            self.assertLess(rules.index(["-d", network, "-j", "REJECT"]), web)
        self.assertIn(["-d", "168.63.129.16/32", "-j", "REJECT"], rules)
        self.assertEqual(rules[-1], ["-j", "REJECT"])

    def test_ntp_is_limited_to_boot_configured_public_servers(self):
        rules = list(EGRESS.rules("172.17.0.2"))
        ntp = [rule for rule in rules if "123" in rule]
        self.assertEqual(ntp, [["-d", server, "-p", "udp", "--dport", "123", "-j", "RETURN"]
                               for server in EGRESS.TIME_SERVERS])
        source = Path(__file__).with_name("benchmark-qemu.sh").read_text()
        self.assertIn("NTP=" + " ".join(EGRESS.TIME_SERVERS), source)
        self.assertIn("restart --no-block systemd-timesyncd.service", source)

    def test_cleanup_refuses_live_controller_before_touching_firewall(self):
        with patch.object(EGRESS, "execute", return_value=subprocess.CompletedProcess([], 0, NAME + "\n", "")) as run:
            with self.assertRaises(ValueError):
                EGRESS.remove(NAME)
        self.assertEqual(run.call_count, 1)

    def test_cleanup_removes_both_source_scoped_hooks(self):
        chain = EGRESS.chain_name(NAME)

        def fake(argv, check=True):
            output = "" if argv[:2] == ["docker", "ps"] else (
                f"-N {chain}\n-A FORWARD -j {chain}\n-A INPUT -j {chain}\n"
                if argv[-1] == "-S" else ""
            )
            return subprocess.CompletedProcess(argv, 0, output, "")

        with patch.object(EGRESS, "execute", side_effect=fake) as run:
            EGRESS.remove(NAME)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(["iptables", "-w", "5", "-D", "FORWARD", "-j", chain], commands)
        self.assertIn(["iptables", "-w", "5", "-D", "INPUT", "-j", chain], commands)
        self.assertIn(["iptables", "-w", "5", "-X", chain], commands)

    def test_invalid_controller_names_are_rejected(self):
        for name in ("other-container", "omg-qemu-run-../host", "--privileged"):
            with self.assertRaises(ValueError):
                EGRESS.chain_name(name)

    def test_network_policy_requires_positive_metadata_counter(self):
        container = dict(Name="/" + NAME, State=dict(Running=True),
                         HostConfig=dict(Privileged=False, CapDrop=["CAP_NET_RAW", "CAP_NET_ADMIN"], Dns=list(EGRESS.RESOLVERS)),
                         NetworkSettings=dict(Networks=dict(bridge=dict(IPAddress="172.17.0.2", GlobalIPv6Address=""))))
        for counts, exits, allowed in (
            ([0, 1], [1], True),
            ([0, 0, 1], [1, 1], True),
            ([0, 0, 0, 0], [1, 1, 1], False),
            ([0, 1], [0], False),
        ):
            counters = iter(counts)
            probes = iter(exits)

            def fake(argv, check=True):
                output = ""
                if argv[:2] == ["docker", "inspect"]:
                    output = json.dumps([container])
                elif "-L" in argv:
                    output = f"{next(counters)} 60 REJECT all -- * * 0.0.0.0/0 169.254.0.0/16\n"
                return subprocess.CompletedProcess(argv, next(probes) if argv[:2] == ["docker", "exec"] else 0, output, "")

            with self.subTest(counts=counts, exits=exits), \
                    patch.object(EGRESS, "execute", side_effect=fake) as calls, \
                    patch.object(EGRESS.time, "sleep") as sleep:
                if allowed:
                    receipt = EGRESS.install(NAME)
                    self.assertTrue(receipt["metadata_block_verified"])
                    self.assertEqual(len(receipt["metadata_probe_attempts"]), len(exits))
                    self.assertGreater(receipt["metadata_probe_attempts"][-1]["reject_count_after"],
                                       receipt["metadata_probe_attempts"][-1]["reject_count_before"])
                else:
                    with self.assertRaisesRegex(ValueError, "metadata (rejection was not observed|connection succeeded)"):
                        EGRESS.install(NAME)
                self.assertEqual(sleep.call_count, max(0, len(exits) - 1) if exits[0] != 0 else 0)
                self.assertEqual(sum(call.args[0][:2] == ["docker", "exec"] for call in calls.call_args_list), len(exits))
                self.assertIn(
                    ["iptables", "-w", "5", "-I", "FORWARD", "1", "-j", EGRESS.chain_name(NAME)],
                    [call.args[0] for call in calls.call_args_list],
                )


if __name__ == "__main__":
    unittest.main()
