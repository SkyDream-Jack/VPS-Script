import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli, firewall, ufw_rollback


class FakeFirewall:
    def __init__(self):
        self.active = False
        self.rules = []
        self.calls = []
        self.competing = None
        self.timer_ok = True
        self.tx_dir = None
        self.foreign_rule = False
        self.nft_entries = []
        self.nft_reads = 0
        self.late_rule = False
        self.fail_snapshot_once = False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        name = Path(args[0]).name
        if name == "ufw" and args[1:] in (("status",), ("status", "verbose")):
            status = "Status: active\n" if self.active else "Status: inactive\n"
            if args[1:] == ("status", "verbose"):
                status += "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
                if self.active:
                    if self.fail_snapshot_once:
                        self.fail_snapshot_once = False
                        return subprocess.CompletedProcess(args, 1, "", "snapshot failed")
                    status += "\n".join(self.rules) + "\n"
            return subprocess.CompletedProcess(args, 0, status, "")
        if name == "nft":
            self.nft_reads += 1
            entries = list(self.nft_entries)
            if self.foreign_rule or (self.late_rule and self.nft_reads > 1):
                entries.append({"rule": {"chain": "INPUT", "table": "filter"}})
            return subprocess.CompletedProcess(args, 0, json.dumps({"nftables": entries}), "")
        if name == "ufw" and args[1] == "allow":
            self.rules.append(args[2])
        elif name == "ufw" and args[1:] == ("--force", "enable"):
            self.active = True
        elif name == "ufw" and args[1:] == ("--force", "disable"):
            self.active = False
        elif name == "systemctl" and args[1] == "is-active":
            if args[2].endswith(".timer"):
                return subprocess.CompletedProcess(args, 0 if self.timer_ok else 3, "active\n" if self.timer_ok else "inactive\n", "")
            active = args[2] == self.competing
            return subprocess.CompletedProcess(args, 0 if active else 3, "active\n" if active else "inactive\n", "")
        elif name == "systemd-run":
            self.tx_dir = Path(args[-2])
        elif name == "python3":
            rc = ufw_rollback.run(args[-2], args[-1], runner=self)
            return subprocess.CompletedProcess(args, rc, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


class FirewallTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in ("run/lock", "run/systemd/system", "var/lib"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.fake = FakeFirewall()
        self.manager = firewall.FirewallManager(self.root, self.fake)
        commands = {"ufw": "/usr/sbin/ufw", "systemctl": "/usr/bin/systemctl", "systemd-run": "/usr/bin/systemd-run", "nft": "/usr/sbin/nft"}
        self.find = patch.object(firewall.checks, "find_command", side_effect=commands.get)
        self.find.start()
        self.addCleanup(self.find.stop)
        real_isfile = os.path.isfile
        self.system_python = patch.object(firewall.os.path, "isfile",
                                          side_effect=lambda path: path == "/usr/bin/python3" or real_isfile(path))
        self.system_python.start()
        self.addCleanup(self.system_python.stop)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def test_enable_then_confirmation_prevents_later_rollback(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.manager.enable(2222, lambda: True)
        self.assertIn("通过端口 2222", output.getvalue())
        self.assertIn("ControlPath=none", output.getvalue())
        self.assertTrue(self.fake.active)
        self.assertIn("2222/tcp", self.fake.rules)
        self.assertTrue((self.fake.tx_dir / "confirmed").exists())
        self.assertEqual(ufw_rollback.run(self.fake.tx_dir, "/usr/sbin/ufw", self.fake), 0)
        self.assertTrue(self.fake.active)

    def test_unconfirmed_restores_inactive_but_keeps_allow_rule(self):
        with self.assertRaisesRegex(firewall.FirewallFailure, "未确认"):
            self.manager.enable(2222, lambda: False)
        self.assertFalse(self.fake.active)
        self.assertIn("2222/tcp", self.fake.rules)
        self.assertTrue((self.fake.tx_dir / "rolled-back").exists())

    def test_timeout_before_confirmation_is_not_reported_as_success(self):
        def timed_out():
            self.assertEqual(ufw_rollback.run(self.fake.tx_dir, "/usr/sbin/ufw", self.fake), 0)
            return True
        with self.assertRaisesRegex(firewall.FirewallFailure, "回滚已"):
            self.manager.enable(2222, timed_out)
        self.assertFalse(self.fake.active)

    def test_external_rule_change_blocks_automatic_disable(self):
        def changed_rules():
            self.fake.rules.append("443/tcp")
            self.assertEqual(ufw_rollback.run(self.fake.tx_dir, "/usr/sbin/ufw", self.fake), 1)
            return True
        with self.assertRaisesRegex(firewall.FirewallFailure, "回滚已"):
            self.manager.enable(2222, changed_rules)
        self.assertTrue(self.fake.active)
        self.assertFalse((self.fake.tx_dir / "confirmed").exists())

    def test_running_other_firewall_blocks_enable(self):
        self.fake.competing = "docker.service"
        with self.assertRaisesRegex(firewall.FirewallFailure, "docker.service"):
            self.manager.enable(2222, lambda: True)
        self.assertFalse(self.fake.active)
        self.assertEqual(self.fake.rules, [])

    def test_unconfirmed_timer_prevents_enable(self):
        self.fake.timer_ok = False
        with self.assertRaisesRegex(firewall.FirewallFailure, "定时器"):
            self.manager.enable(2222, lambda: True)
        self.assertFalse(self.fake.active)
        self.assertEqual(self.fake.rules, [])

    def test_foreign_nft_rule_blocks_enable(self):
        self.fake.foreign_rule = True
        with self.assertRaisesRegex(firewall.FirewallFailure, "现有 nftables 规则"):
            self.manager.enable(2222, lambda: True)
        self.assertFalse(self.fake.active)
        self.assertEqual(self.fake.rules, [])

    def test_empty_base_chain_with_drop_policy_blocks_enable(self):
        self.fake.nft_entries = [{"chain": {"family": "inet", "table": "foreign", "name": "input",
                                                   "type": "filter", "hook": "input", "policy": "drop"}}]
        with self.assertRaisesRegex(firewall.FirewallFailure, "挂钩链"):
            self.manager.enable(2222, lambda: True)
        self.assertEqual(self.fake.rules, [])
        self.assertFalse(self.fake.active)
        self.assertFalse(any("systemd-run" in args[0] for args in self.fake.calls))

    def test_ufw_like_chain_name_does_not_prove_rule_ownership(self):
        self.fake.nft_entries = [{"rule": {"chain": "ufw-custom", "table": "foreign"}}]
        with self.assertRaisesRegex(firewall.FirewallFailure, "现有 nftables 规则"):
            self.manager.enable(2222, lambda: True)
        self.assertEqual(self.fake.rules, [])

    def test_unrecognized_nft_object_blocks_enable(self):
        self.fake.nft_entries = [{"flowtable": {"family": "inet", "name": "custom"}}]
        with self.assertRaisesRegex(firewall.FirewallFailure, "未检查的 nftables 对象"):
            self.manager.enable(2222, lambda: True)
        self.assertEqual(self.fake.rules, [])

    def test_rule_created_during_timer_setup_blocks_enable(self):
        self.fake.late_rule = True
        with self.assertRaisesRegex(firewall.FirewallFailure, "现有 nftables 规则"):
            self.manager.enable(2222, lambda: True)
        self.assertEqual(self.fake.rules, [])
        self.assertFalse(self.fake.active)
        self.assertTrue((self.fake.tx_dir / "expired").exists())

    def test_failed_snapshot_cannot_be_claimed_as_automatic_recovery(self):
        self.fake.fail_snapshot_once = True
        with self.assertRaises(firewall.FirewallFailure):
            self.manager.enable(2222, lambda: True)
        self.assertTrue(self.fake.active)
        self.assertFalse((self.fake.tx_dir / "rolled-back").exists())
        self.assertFalse((self.fake.tx_dir / "confirmed").exists())

    def test_existing_active_ufw_is_not_changed(self):
        self.fake.active = True
        self.manager.enable(2222, lambda: True)
        self.assertEqual(self.fake.rules, [])
        self.assertFalse(any("systemd-run" in args[0] for args in self.fake.calls))

    def test_missing_system_python_blocks_enable(self):
        with patch.object(firewall.os.path, "isfile", return_value=False), \
             self.assertRaisesRegex(firewall.FirewallFailure, "systemd 与 /usr/bin/python3"):
            self.manager.enable(2222, lambda: True)
        self.assertEqual(self.fake.rules, [])
        self.assertFalse(self.fake.active)

    def test_validates_remote_session_and_port_range(self):
        self.assertEqual(firewall.ssh_session_port("192.0.2.1 40000 192.0.2.2 2222"), 2222)
        self.assertEqual(firewall.port_rule(20000, 20100, "udp"), "20000:20100/udp")
        for value in ("", "evil 1 2 3", "192.0.2.1 0 192.0.2.2 22"):
            with self.subTest(value=value), self.assertRaises(firewall.FirewallFailure):
                firewall.ssh_session_port(value)
        with self.assertRaises(firewall.FirewallFailure):
            firewall.port_rule(22, 70000, "tcp")

    def test_demo_never_changes_firewall(self):
        with patch("builtins.input", side_effect=["2", "3", "0"]), \
             patch.object(firewall, "enable", side_effect=AssertionError("must not run")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            cli.security_menu(demo=True, experimental=True)
        self.assertIn("不会修改防火墙", out.getvalue())


if __name__ == "__main__":
    unittest.main()
