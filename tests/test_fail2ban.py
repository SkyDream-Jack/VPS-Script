import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli, fail2ban


class FakeClient:
    def __init__(self, root):
        self.root = root
        self.names = []
        self.fail_validation = False
        self.fail_jail = False
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        name = Path(args[0]).name
        if name == "systemctl":
            return subprocess.CompletedProcess(args, 0, "active\n", "")
        if name == "sshd":
            return subprocess.CompletedProcess(args, 0, "port 22\nport 2222\n", "")
        if name == "fail2ban-client" and args[1:] == ("status",):
            return subprocess.CompletedProcess(args, 0, "`- Jail list: " + ", ".join(self.names) + "\n", "")
        if name == "fail2ban-client" and args[1:] == ("-t",) and self.fail_validation:
            return subprocess.CompletedProcess(args, 1, "", "invalid config")
        if name == "fail2ban-client" and args[1:] == ("reload",):
            config = self.root / "etc/fail2ban/jail.d/50-vps-script-sshd.local"
            self.names = [fail2ban.JAIL] if config.exists() else []
        if name == "fail2ban-client" and args[1:] == ("status", fail2ban.JAIL) and self.fail_jail:
            return subprocess.CompletedProcess(args, 1, "", "not running")
        return subprocess.CompletedProcess(args, 0, "", "")


class Fail2banTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in ("run/lock", "etc/fail2ban/jail.d"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        self.fake = FakeClient(self.root)
        self.manager = fail2ban.Fail2banManager(self.root, self.fake)
        commands = {"fail2ban-client": "/usr/bin/fail2ban-client", "sshd": "/usr/sbin/sshd", "systemctl": "/usr/bin/systemctl"}
        self.find = patch.object(fail2ban.checks, "find_command", side_effect=commands.get)
        self.find.start()
        self.addCleanup(self.find.stop)

    def test_create_validates_and_checks_jail(self):
        self.manager.configure()
        self.assertIn("port = 22,2222", self.manager.config.read_text(encoding="utf-8"))
        self.assertIn(fail2ban.JAIL, self.fake.names)
        self.assertTrue(any(args[1:] == ("-t",) for args in self.fake.calls))

    def test_existing_ssh_jail_is_preserved(self):
        self.fake.names = ["sshd"]
        result = self.manager.configure()
        self.assertIn("没有覆盖", result)
        self.assertFalse(self.manager.config.exists())
        self.assertFalse(any("reload" in args for args in self.fake.calls))

    def test_other_jail_blocks_reload(self):
        self.fake.names = ["nginx-auth"]
        with self.assertRaisesRegex(fail2ban.Fail2banFailure, "其他活动 jail"):
            self.manager.configure()
        self.assertFalse(self.manager.config.exists())

    def test_invalid_configuration_is_removed(self):
        self.fake.fail_validation = True
        with self.assertRaises(fail2ban.Fail2banFailure):
            self.manager.configure()
        self.assertFalse(self.manager.config.exists())

    def test_jail_failure_rolls_back_owned_file(self):
        self.fake.fail_jail = True
        with self.assertRaises(fail2ban.Fail2banFailure):
            self.manager.configure()
        self.assertFalse(self.manager.config.exists())
        self.assertEqual(self.fake.names, [])

    def test_invalid_ports_and_unknown_status_are_rejected(self):
        with self.assertRaises(fail2ban.Fail2banFailure):
            fail2ban.ssh_ports("port 99999\n")
        with self.assertRaises(fail2ban.Fail2banFailure):
            fail2ban.jail_names("unknown output")

    def test_jail_config_records_banaction(self):
        text = fail2ban.jail_config((22, 2222), "ufw").decode("utf-8")
        self.assertIn("port = 22,2222", text)
        self.assertIn("banaction = ufw", text)
        with self.assertRaises(fail2ban.Fail2banFailure):
            fail2ban.jail_config((22,), "shell")

    def test_refresh_ports_updates_only_owned_jail(self):
        self.manager.config.write_text(
            fail2ban.jail_config((22,), "iptables-multiport").decode("utf-8"), encoding="utf-8")
        result = self.manager.refresh_ports()
        self.assertIn("22, 2222", result)
        self.assertIn("port = 22,2222", self.manager.config.read_text(encoding="utf-8"))
        self.assertTrue(any(args[1:] == ("reload",) for args in self.fake.calls))

    def test_unban_validates_ip_and_uses_existing_jail(self):
        self.fake.names = ["sshd"]
        result = self.manager.unban("192.0.2.9")
        self.assertIn("sshd", result)
        with self.assertRaises(fail2ban.Fail2banFailure):
            self.manager.unban("not-an-ip")

    def test_demo_never_changes_fail2ban(self):
        with patch("builtins.input", side_effect=["1", "0"]), \
             patch.object(fail2ban, "configure", side_effect=AssertionError("must not run")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            cli.fail2ban_menu(demo=True, experimental=True)
        self.assertIn("不会读取本机、联网或执行修改", out.getvalue())


if __name__ == "__main__":
    unittest.main()
