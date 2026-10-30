import contextlib
import copy
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
from vps_admin import backup, backup_access, fail2ban, firewall, ssh
from test_fail2ban import FakeClient
from test_firewall import FakeFirewall
from test_ssh import FakeSSH


class AccessFixture(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for name in ("run/lock", "run/systemd/system", "var/lib", "etc/ssh/sshd_config.d",
                     "etc/default", "etc/ufw", "etc/fail2ban/jail.d"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/ssh/sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\n")
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 40000 192.0.2.2 22", "SUDO_USER": "root"}))
        self.store = backup.Store(self.root)

    def track(self, module, action, operation, **kwargs):
        previous = {row["id"] for row in self.store.list()}
        backup.track(module, action, operation, adapter=self.adapter, store=self.store, **kwargs)
        created = [row for row in self.store.list() if row["id"] not in previous]
        self.assertEqual(len(created), 1)
        return self.store.read(created[0]["id"])


class SSHHistoryTest(AccessFixture):
    def setUp(self):
        super().setUp()
        self.fake = FakeSSH(self.root)
        self.manager = ssh.SSHManager(self.root, self.fake)
        commands = {"sshd": "/usr/sbin/sshd", "ss": "/usr/bin/ss", "systemctl": "/usr/bin/systemctl",
                    "systemd-run": "/usr/bin/systemd-run"}
        self.stack.enter_context(patch.object(ssh.checks, "find_command", side_effect=commands.get))
        self.adapter = backup_access.SSHAdapter(self.root, self.manager, verify=lambda: True)

    def add_port(self):
        return self.track("ssh", "add-port", lambda: self.manager.change(user="root", address="192.0.2.1",
                          current_port=22, new_port=2222, verify=lambda: True))

    def test_restore_new_dropin_removes_it_with_a_new_verified_transaction(self):
        record = self.add_port()
        first = self.fake.tx_dir
        self.assertTrue(record["restore_supported"])
        backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertFalse(self.fake.target.exists())
        self.assertEqual(self.fake.ports, {22})
        self.assertNotEqual(self.fake.tx_dir, first)
        self.assertTrue((self.fake.tx_dir / "confirmed").exists())
        self.assertEqual(self.store.read(record["id"])["state"], "restored")

    def test_unconfirmed_restore_reinstates_the_current_file_and_listeners(self):
        record = self.add_port()
        after = self.fake.target.read_bytes()
        self.adapter.verify = lambda: False
        with self.assertRaisesRegex(backup.BackupFailure, "未确认"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.fake.target.read_bytes(), after)
        self.assertEqual(self.fake.ports, {22, 2222})
        self.assertTrue((self.fake.tx_dir / "rolled-back").exists())
        self.assertEqual(self.store.read(record["id"])["state"], "completed")

    def test_restore_refuses_to_remove_current_connection_port(self):
        record = self.add_port()
        before_calls = len(self.fake.calls)
        with patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 40000 192.0.2.2 2222"}), \
                self.assertRaisesRegex(backup.BackupFailure, "不保留当前 SSH 端口"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.fake.ports, {22, 2222})
        self.assertFalse(any(Path(args[0]).name == "systemd-run" for args in self.fake.calls[before_calls:]))

    def test_external_configuration_drift_blocks_restore(self):
        record = self.add_port()
        (self.root / "etc/ssh/sshd_config.d/custom.conf").write_text("UseDNS no\n")
        with self.assertRaisesRegex(backup.BackupFailure, "快照不同"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.fake.ports, {22, 2222})

    def test_live_listener_or_service_mode_drift_blocks_restore(self):
        record = self.add_port()
        self.fake.ports.remove(2222)
        with self.assertRaisesRegex(backup.BackupFailure, "快照不同"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.fake.ports.add(2222)
        self.fake.socket_mode = True
        with self.assertRaisesRegex(backup.BackupFailure, "快照不同"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)

    def test_key_only_history_restores_previous_authentication_configuration(self):
        self.manager.change(user="root", address="192.0.2.1", current_port=22, new_port=2222, verify=lambda: True)
        original = self.fake.target.read_bytes()
        record = self.track("ssh", "key-only", lambda: self.manager.change(user="root", address="192.0.2.1",
                            current_port=22, key_only=True, verify=lambda: True))
        backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.fake.target.read_bytes(), original)
        self.assertNotIn(b"PasswordAuthentication", self.fake.target.read_bytes())


class SnapshotFirewall(FakeFirewall):
    def __init__(self, root):
        super().__init__()
        self.root = root
        (root / "etc/default/ufw").write_text('DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n')
        self.persist()

    def persist(self):
        (self.root / "etc/ufw/ufw.conf").write_text("ENABLED=" + ("yes" if self.active else "no") + "\n")
        (self.root / "etc/ufw/user.rules").write_text("\n".join(self.rules) + "\n")
        (self.root / "etc/ufw/user6.rules").write_text("\n".join(self.rules) + "\n")

    def __call__(self, args, **kwargs):
        if Path(args[0]).name == "ufw" and args[1:] == ("show", "added"):
            self.calls.append(args)
            output = "Added user rules (see 'ufw status' for running firewall):\n"
            output += "\n".join("ufw allow " + rule for rule in self.rules) + "\n"
            return subprocess.CompletedProcess(args, 0, output, "")
        result = super().__call__(args, **kwargs)
        if Path(args[0]).name == "ufw" and args[1] in ("allow", "delete", "--force"):
            self.persist()
        return result


class UFWHistoryTest(AccessFixture):
    def setUp(self):
        super().setUp()
        self.fake = SnapshotFirewall(self.root)
        self.manager = firewall.FirewallManager(self.root, self.fake)
        self.adapter = backup_access.UFWAdapter(self.root, self.manager)
        commands = {"ufw": "/usr/sbin/ufw", "systemctl": "/usr/bin/systemctl", "systemd-run": "/usr/bin/systemd-run", "nft": "/usr/sbin/nft"}
        self.stack.enter_context(patch.object(firewall.checks, "find_command", side_effect=commands.get))
        real_isfile = os.path.isfile
        self.stack.enter_context(patch.object(firewall.os.path, "isfile", side_effect=lambda path: path == "/usr/bin/python3" or real_isfile(path)))

    def test_new_allow_can_be_removed_without_changing_other_rules(self):
        self.fake.active = True
        self.fake.rules = ["22/tcp", "53/udp"]
        self.fake.persist()
        record = self.track("ufw", "allow", lambda: self.manager.allow(443, 443, "tcp"))
        self.assertTrue(record["restore_supported"])
        backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertTrue(self.fake.active)
        self.assertEqual(self.fake.rules, ["22/tcp", "53/udp"])
        self.assertFalse(any("reset" in args or "flush" in args for args in self.fake.calls))

    def test_current_ssh_allow_cannot_be_removed_by_history(self):
        self.fake.active = True
        self.fake.persist()
        record = self.track("ufw", "allow", lambda: self.manager.allow(22, 22, "tcp"))
        with self.assertRaisesRegex(backup.BackupFailure, "当前 SSH 端口"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.fake.rules, ["22/tcp"])

    def test_restoring_initial_enable_disables_ufw_but_keeps_allow(self):
        record = self.track("ufw", "enable", lambda: self.manager.enable(22, lambda: True))
        self.assertTrue(record["restore_supported"])
        result = backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertIn("allow 规则保留", result)
        self.assertFalse(self.fake.active)
        self.assertEqual(self.fake.rules, ["22/tcp"])

    def test_deleted_allow_is_backup_only_and_not_appended_on_restore(self):
        self.fake.rules = ["443/tcp"]
        self.fake.persist()
        record = self.track("ufw", "delete", lambda: self.manager.delete(443, 443, "tcp"), restore_supported=False)
        self.assertFalse(record["restore_supported"])
        with self.assertRaisesRegex(backup.BackupFailure, "不支持自动恢复"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.fake.rules, [])

    def test_later_rules_or_raw_file_changes_block_restore(self):
        record = self.track("ufw", "allow", lambda: self.manager.allow(443, 443, "tcp"))
        (self.root / "etc/ufw/user.rules").write_text("external rule or counter change\n")
        with self.assertRaisesRegex(backup.BackupFailure, "快照不同"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.fake.rules, ["443/tcp"])

    def test_complex_rules_and_reordering_are_not_automatically_reversible(self):
        before = self.adapter.capture()
        after = copy.deepcopy(before)
        after["rules"] = ["ufw allow from 192.0.2.1 to any port 443"]
        self.assertIsNotNone(self.adapter.recovery_reason(before, after))
        before["rules"] = ["ufw allow 22/tcp"]
        after["rules"] = ["ufw allow 443/tcp", "ufw allow 22/tcp"]
        self.assertIsNotNone(self.adapter.recovery_reason(before, after))


class SnapshotJail(FakeClient):
    def __init__(self, root):
        super().__init__(root)
        self.ports = (22, 2222)
        self.ufw_active = False

    def __call__(self, args, **kwargs):
        if Path(args[0]).name == "sshd":
            self.calls.append(args)
            return subprocess.CompletedProcess(args, 0, "".join(f"port {port}\n" for port in self.ports), "")
        if Path(args[0]).name == "ufw":
            self.calls.append(args)
            return subprocess.CompletedProcess(args, 0, "Status: active\n" if self.ufw_active else "Status: inactive\n", "")
        return super().__call__(args, **kwargs)


class Fail2banHistoryTest(AccessFixture):
    def setUp(self):
        super().setUp()
        self.fake = SnapshotJail(self.root)
        self.manager = fail2ban.Fail2banManager(self.root, self.fake)
        self.adapter = backup_access.Fail2banAdapter(self.root, self.manager)
        commands = {"fail2ban-client": "/usr/bin/fail2ban-client", "sshd": "/usr/sbin/sshd",
                    "systemctl": "/usr/bin/systemctl", "ufw": "/usr/sbin/ufw"}
        self.stack.enter_context(patch.object(fail2ban.checks, "find_command", side_effect=commands.get))

    def test_creation_can_be_restored_by_removing_only_project_jail(self):
        record = self.track("fail2ban", "configure", self.manager.configure)
        backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertFalse(self.manager.config.exists())
        self.assertEqual(self.fake.names, [])
        self.assertFalse(any("stop" in args for args in self.fake.calls))

    def port_change_record(self):
        self.manager.config.write_bytes(fail2ban.jail_config((22,), "iptables-multiport"))
        self.fake.names = [fail2ban.JAIL]
        return self.track("fail2ban", "refresh-ports", self.manager.refresh_ports)

    def test_old_jail_ports_must_match_current_ssh_before_restore(self):
        record = self.port_change_record()
        current = self.manager.config.read_bytes()
        with self.assertRaisesRegex(backup.BackupFailure, "端口与当前 SSH 不一致"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.manager.config.read_bytes(), current)

    def test_matching_ports_allow_exact_project_config_restore(self):
        record = self.port_change_record()
        self.fake.ports = (22,)
        backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.manager.config.read_bytes(), fail2ban.jail_config((22,), "iptables-multiport"))

    def test_incompatible_firewall_action_blocks_restore(self):
        record = self.port_change_record()
        self.fake.ports = (22,)
        self.fake.ufw_active = True
        with self.assertRaisesRegex(backup.BackupFailure, "封禁动作与当前防火墙不兼容"):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)

    def test_failed_reload_validation_restores_current_project_config(self):
        record = self.track("fail2ban", "configure", self.manager.configure)
        current = self.manager.config.read_bytes()
        self.fake.fail_validation = True
        with self.assertRaises(backup.BackupFailure):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.manager.config.read_bytes(), current)
        self.assertEqual(self.fake.names, [fail2ban.JAIL])

    def test_other_jails_are_not_eligible_for_reload_recovery(self):
        before = self.adapter.capture()
        self.manager.configure()
        after = self.adapter.capture()
        before["jails"] = ["web"]
        after["jails"].append("web")
        self.assertIn("其他活动 jail", self.adapter.recovery_reason(before, after))

    def test_missing_project_jail_refresh_is_noop_without_history_or_service_calls(self):
        with patch.object(fail2ban, "Fail2banManager", return_value=self.manager), \
                patch.object(backup, "track", side_effect=AssertionError("must not create history")):
            self.assertEqual(fail2ban.refresh_ports(), 0)
        self.assertEqual(self.fake.calls, [])

    def test_unreadable_project_jail_is_not_reported_as_missing(self):
        with patch.object(fail2ban, "Fail2banManager", return_value=self.manager), \
                patch.object(fail2ban.os, "lstat", side_effect=PermissionError("denied")), \
                patch.object(backup, "track", side_effect=AssertionError("must not create history")):
            self.assertEqual(fail2ban.refresh_ports(), 1)
        self.assertEqual(self.fake.calls, [])


class AccessEntryPointTest(unittest.TestCase):
    def test_cancelled_firewall_actions_do_not_create_history(self):
        with patch.object(firewall.packages, "preflight", return_value=None), \
                patch.object(backup, "track", side_effect=AssertionError("unconfirmed history")), \
                patch("builtins.input", return_value="NO"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(firewall.allow(443, 443, "tcp", experimental=True), 0)
            self.assertEqual(firewall.delete(443, 443, "tcp", experimental=True), 0)

    def test_delete_confirmed_entry_tracks_backup_only_and_calls_manager(self):
        def track(module, action, operation, **kwargs):
            self.assertEqual((module, action), ("ufw", "delete"))
            self.assertFalse(kwargs["restore_supported"])
            return operation()
        with patch.object(firewall.packages, "preflight", return_value=None), \
                patch.object(backup, "track", side_effect=track) as tracked, \
                patch.object(firewall, "FirewallManager") as manager, \
                patch("builtins.input", return_value="YES"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(firewall.delete(443, 443, "tcp", experimental=True), 0)
        tracked.assert_called_once()
        manager.return_value.delete.assert_called_once_with(443, 443, "tcp")

    def test_cancelled_ssh_change_does_not_open_firewall_or_record(self):
        with patch.object(ssh.packages, "preflight", return_value=None), \
                patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 40000 192.0.2.2 22"}), \
                patch.object(backup, "track", side_effect=AssertionError("unconfirmed mutation")), \
                patch.object(firewall, "FirewallManager", side_effect=AssertionError("unconfirmed firewall")), \
                patch("builtins.input", return_value="NO"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ssh.change(new_port=2222, open_firewall=True, experimental=True), 0)

    def test_unban_is_audit_only_and_does_not_record_address(self):
        def track(module, action, operation, **kwargs):
            self.assertEqual((module, action), ("fail2ban", "unban"))
            self.assertFalse(kwargs["restore_supported"])
            self.assertNotIn("192.0.2.10", json.dumps(kwargs["details"]))
            return operation()
        with patch.object(fail2ban.packages, "preflight", return_value=None), \
                patch.object(backup, "track", side_effect=track), \
                patch.object(fail2ban, "Fail2banManager") as manager, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fail2ban.unban("192.0.2.10", experimental=True), 0)
        manager.return_value.unban.assert_called_once_with("192.0.2.10")


if __name__ == "__main__":
    unittest.main()
