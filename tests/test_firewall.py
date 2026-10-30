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
        self.active_defaults = "Default: deny (incoming), allow (outgoing), disabled (routed)\n"

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        name = Path(args[0]).name
        if name == "ufw" and args[1:] in (("status",), ("status", "verbose")):
            status = "Status: active\n" if self.active else "Status: inactive\n"
            if args[1:] == ("status", "verbose") and self.active:
                status += self.active_defaults
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
        elif name == "ufw" and args[1:3] == ("delete", "allow"):
            self.rules.remove(args[3])
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
        for path in ("run/lock", "run/systemd/system", "var/lib", "etc/default"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.defaults_file = self.root / "etc/default/ufw"
        self.defaults_file.write_text('DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n', encoding="utf-8")
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
        self.assertEqual(self.manager.verbose_status("/usr/sbin/ufw"), "Status: inactive\n")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.manager.enable(2222, lambda: True)
        self.assertIn("通过端口 2222", output.getvalue())
        self.assertIn("ControlPath=none", output.getvalue())
        self.assertTrue(self.fake.active)
        self.assertIn("2222/tcp", self.fake.rules)
        self.assertTrue((self.fake.tx_dir / "confirmed").exists())
        self.assertEqual(ufw_rollback.run(self.fake.tx_dir, "/usr/sbin/ufw", self.fake), 0)
        self.assertTrue(self.fake.active)

    def test_enable_rejects_non_deny_incoming_before_any_changes(self):
        for policy in ("ACCEPT", "REJECT"):
            with self.subTest(policy=policy):
                self.defaults_file.write_text(f'DEFAULT_INPUT_POLICY="{policy}"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n')
                with self.assertRaisesRegex(firewall.FirewallFailure, "默认入站策略不是 deny"):
                    self.manager.enable(22, lambda: True)
        self.assertEqual(self.fake.rules, [])
        self.assertFalse(self.fake.active)
        self.assertFalse(any("systemd-run" in args[0] for args in self.fake.calls))

    def test_static_default_config_parses_comments_quotes_and_other_values(self):
        self.defaults_file.write_text(
            '# UFW settings\nIPV6=yes\nDEFAULT_INPUT_POLICY="DROP" # incoming\n'
            "DEFAULT_OUTPUT_POLICY='ACCEPT'\nIPT_MODULES=\"nf_conntrack_ftp nf_nat_ftp\"\n", encoding="utf-8")
        self.assertEqual(self.manager.configured_defaults(), {"incoming": "deny", "outgoing": "allow"})

    def test_invalid_default_config_blocks_enable(self):
        configs = (
            'DEFAULT_INPUT_POLICY="DROP"\n',
            'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_INPUT_POLICY="ACCEPT"\n',
            'DEFAULT_INPUT_POLICY="${POLICY}"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n',
            'DEFAULT_INPUT_POLICY="$(touch /tmp/should-not-run)"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n',
            'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n. /tmp/other-defaults\n',
            'DEFAULT_INPUT_POLICY="DROP"; DEFAULT_INPUT_POLICY="ACCEPT"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n',
            'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT\n',
        )
        for config in configs:
            with self.subTest(config=config):
                self.defaults_file.write_text(config, encoding="utf-8")
                with self.assertRaises(firewall.FirewallFailure):
                    self.manager.enable(22, lambda: True)
        self.assertEqual(self.fake.rules, [])
        self.assertFalse(self.fake.active)
        self.assertFalse(any("systemd-run" in args[0] for args in self.fake.calls))

    def test_missing_and_unsafe_default_files_block_enable(self):
        self.defaults_file.unlink()
        with self.assertRaisesRegex(firewall.FirewallFailure, "无法安全读取"):
            self.manager.enable(22, lambda: True)
        other = self.root / "default-ufw"
        other.write_text('DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n')
        self.defaults_file.symlink_to(other)
        with self.assertRaisesRegex(firewall.FirewallFailure, "无法安全读取"):
            self.manager.enable(22, lambda: True)
        self.defaults_file.unlink()
        self.defaults_file.write_bytes(other.read_bytes())
        self.defaults_file.chmod(0o666)
        with self.assertRaisesRegex(firewall.FirewallFailure, "可信的普通文件"):
            self.manager.enable(22, lambda: True)
        self.assertFalse(self.fake.active)
        self.assertEqual(self.fake.rules, [])

    def test_changed_default_config_before_apply_blocks_enable(self):
        initial = {"incoming": "deny", "outgoing": "allow"}
        changed = {"incoming": "allow", "outgoing": "allow"}
        with patch.object(self.manager, "configured_defaults", side_effect=[initial, changed]), \
                self.assertRaisesRegex(firewall.FirewallFailure, "操作期间发生变化"):
            self.manager.enable(22, lambda: True)
        self.assertFalse(self.fake.active)
        self.assertEqual(self.fake.rules, [])
        self.assertTrue((self.fake.tx_dir / "expired").exists())

    def test_unexpected_live_defaults_trigger_rollback(self):
        self.fake.active_defaults = "Default: allow (incoming), allow (outgoing), disabled (routed)\n"
        verified = []
        with self.assertRaisesRegex(firewall.FirewallFailure, "默认策略与预检不一致"):
            self.manager.enable(22, lambda: verified.append(True))
        self.assertFalse(self.fake.active)
        self.assertEqual(verified, [])
        self.assertTrue((self.fake.tx_dir / "rolled-back").exists())

    def test_delete_current_ssh_port_or_containing_range_is_blocked(self):
        self.fake.active = True
        self.fake.rules = ["22/tcp", "20:25/tcp", "22:25/tcp", "20:22/tcp"]
        with patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 40000 192.0.2.2 22"}):
            for start, end in ((22, 22), (20, 25), (22, 25), (20, 22)):
                with self.subTest(start=start, end=end), \
                        self.assertRaisesRegex(firewall.FirewallFailure, "当前 SSH 端口 22"):
                    self.manager.delete(start, end, "tcp")
        self.assertEqual(len(self.fake.rules), 4)
        self.assertFalse(any("delete" in args for args in self.fake.calls))

    def test_active_tcp_deletion_requires_valid_ssh_context(self):
        self.fake.active = True
        self.fake.rules = ["443/tcp"]
        for value in ("", "invalid", "192.0.2.1 40000 192.0.2.2 0"):
            with self.subTest(value=value), patch.dict(os.environ, {"SSH_CONNECTION": value}), \
                    self.assertRaisesRegex(firewall.FirewallFailure, "无法确认当前 SSH 端口"):
                self.manager.delete(443, 443, "tcp")
        self.assertEqual(self.fake.rules, ["443/tcp"])
        self.assertFalse(any("delete" in args for args in self.fake.calls))

    def test_active_tcp_deletion_allows_another_port(self):
        self.fake.active = True
        self.fake.rules = ["22/tcp", "443/tcp"]
        with patch.dict(os.environ, {"SSH_CONNECTION": "2001:db8::1 40000 2001:db8::2 22"}):
            self.manager.delete(443, 443, "tcp")
        self.assertEqual(self.fake.rules, ["22/tcp"])

    def test_active_udp_deletion_does_not_affect_ssh_tcp(self):
        self.fake.active = True
        self.fake.rules = ["22/tcp", "22/udp"]
        with patch.dict(os.environ, {}, clear=True):
            self.manager.delete(22, 22, "udp")
        self.assertEqual(self.fake.rules, ["22/tcp"])

    def test_inactive_rule_cleanup_does_not_require_ssh_context(self):
        self.fake.rules = ["22/tcp"]
        with patch.dict(os.environ, {}, clear=True):
            self.manager.delete(22, 22, "tcp")
        self.assertEqual(self.fake.rules, [])
        self.assertFalse(self.fake.active)

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
        self.defaults_file.unlink()
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
