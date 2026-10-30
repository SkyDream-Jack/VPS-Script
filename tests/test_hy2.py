import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli, hy2


class FakeNet:
    def __init__(self):
        self.active = False
        self.extra_conflict = False
        self.counter = 0
        self.rule_target = 443
        self.fail_enable = False
        self.nftables_enabled = False
        self.calls = []

    def table(self, family):
        return {"nftables": [
            {"metainfo": {"version": "test"}},
            {"table": {"family": family, "name": hy2.TABLE, "handle": 15}},
            {"chain": {"family": family, "table": hy2.TABLE, "name": "prerouting", "type": "nat", "hook": "prerouting", "handle": 8}},
            {"rule": {"family": family, "table": hy2.TABLE, "chain": "prerouting", "handle": 9,
                      "expr": [{"counter": {"packets": self.counter, "bytes": self.counter * 80}}, {"redirect": {"port": self.rule_target}}]}},
        ]}

    def ruleset(self):
        entries = [{"metainfo": {"version": "test"}}]
        if self.active:
            entries += self.table("ip")["nftables"][1:]
        if self.extra_conflict:
            entries += [{"chain": {"family": "ip", "table": "foreign", "name": "pre", "type": "nat", "hook": "prerouting"}},
                        {"rule": {"family": "ip", "table": "foreign", "chain": "pre", "expr": []}}]
        return {"nftables": entries}

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        command = Path(args[0]).name
        if command == "nft" and args[1:] == ("-j", "list", "ruleset"):
            return subprocess.CompletedProcess(args, 0, json.dumps(self.ruleset()), "")
        if command == "nft" and args[1:4] == ("-j", "list", "table"):
            return subprocess.CompletedProcess(args, 0, json.dumps(self.table(args[4])), "")
        if command == "ip":
            output = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.2"}]}]
            return subprocess.CompletedProcess(args, 0, json.dumps(output), "")
        if command == "ss":
            return subprocess.CompletedProcess(args, 0, "UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n", "")
        if command == "systemctl" and args[1] == "is-active":
            return subprocess.CompletedProcess(args, 3, "inactive\n", "")
        if command == "systemctl" and args[1] == "is-enabled":
            return subprocess.CompletedProcess(args, 0 if self.nftables_enabled else 1,
                                               "enabled\n" if self.nftables_enabled else "disabled\n", "")
        if command == "systemctl" and "enable" in args:
            if self.fail_enable:
                return subprocess.CompletedProcess(args, 1, "", "failed")
            self.active = True
        if command == "systemctl" and "disable" in args:
            self.active = False
        return subprocess.CompletedProcess(args, 0, "", "")


class Hy2Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in ("run/lock", "var/lib", "etc/systemd/system"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.fake = FakeNet()
        self.manager = hy2.Hy2Manager(self.root, self.fake)
        commands = {"nft": "/usr/sbin/nft", "ip": "/usr/sbin/ip", "ss": "/usr/bin/ss", "systemctl": "/usr/bin/systemctl"}
        self.find = patch.object(hy2.checks, "find_command", side_effect=commands.get)
        self.find.start()
        self.addCleanup(self.find.stop)
        self.spec = hy2.HopSpec("eth0", 20000, 20100, 443, ("ip",))

    def test_apply_and_remove_only_own_files(self):
        other = self.root / "etc/systemd/system/unrelated.service"
        other.write_text("keep\n", encoding="utf-8")
        self.manager.apply(self.spec)
        self.assertTrue(self.fake.active)
        self.assertEqual(self.manager.config.read_bytes(), hy2.nft_config(self.spec))
        self.fake.counter = 123
        self.manager.remove()
        self.assertFalse(self.fake.active)
        self.assertFalse(self.manager.config.exists())
        self.assertFalse(self.manager.state.exists())
        self.assertEqual(other.read_text(encoding="utf-8"), "keep\n")

    def test_foreign_nat_rules_stop_before_changes(self):
        self.fake.extra_conflict = True
        with self.assertRaisesRegex(hy2.Hy2Failure, "其他 NAT"):
            self.manager.apply(self.spec)
        self.assertFalse(self.manager.config.exists())
        self.assertFalse(self.fake.active)

    def test_enabled_nftables_service_blocks_persistent_rule(self):
        self.fake.nftables_enabled = True
        with self.assertRaisesRegex(hy2.Hy2Failure, "开机时重置"):
            self.manager.apply(self.spec)
        self.assertFalse(self.manager.config.exists())

    def test_external_rule_edit_blocks_removal(self):
        self.manager.apply(self.spec)
        self.fake.rule_target = 444
        with self.assertRaisesRegex(hy2.Hy2Failure, "外部修改"):
            self.manager.remove()
        self.assertTrue(self.fake.active)
        self.assertTrue(self.manager.state.exists())

    def test_failed_enable_is_cleaned_up(self):
        self.fake.fail_enable = True
        with self.assertRaisesRegex(hy2.Hy2Failure, "应用未完成"):
            self.manager.apply(self.spec)
        self.assertFalse(self.fake.active)
        self.assertFalse(self.manager.state.exists())
        self.assertFalse(self.manager.config.exists())
        self.assertFalse(self.manager.unit.exists())

    def test_range_cannot_steal_other_udp_listener(self):
        with self.assertRaisesRegex(hy2.Hy2Failure, "监听端口冲突"):
            hy2.inspect_listeners(self.spec, "ip", [("0.0.0.0", 443), ("0.0.0.0", 20001)], set())

    def test_target_must_be_listening_on_interface(self):
        with self.assertRaisesRegex(hy2.Hy2Failure, "未确认目标"):
            hy2.inspect_listeners(self.spec, "ip", [("127.0.0.1", 443)], {"192.0.2.2"})

    def test_input_rejects_interface_injection_and_invalid_ranges(self):
        for spec in (hy2.HopSpec('eth0"; flush ruleset', 1, 2, 443, ("ip",)),
                     hy2.HopSpec("eth0", 200, 100, 443, ("ip",)),
                     hy2.HopSpec("eth0", 1, 65536, 443, ("ip",))):
            with self.subTest(spec=spec), self.assertRaises(hy2.Hy2Failure):
                hy2.nft_config(spec)

    def test_single_port_and_ipv6_are_rendered(self):
        spec = hy2.HopSpec("eth0", 20000, 20000, 443, ("ip", "ip6"))
        config = hy2.nft_config(spec).decode()
        self.assertIn("udp dport 20000 counter", config)
        self.assertIn("table ip6", config)

    def test_demo_never_changes_rules(self):
        with patch("builtins.input", side_effect=["1", "2", "0"]), \
             patch.object(hy2, "change", side_effect=AssertionError("must not run")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            cli.hy2_menu(demo=True, experimental=True)
        self.assertIn("不会读取本机、联网或执行修改", out.getvalue())


if __name__ == "__main__":
    unittest.main()
