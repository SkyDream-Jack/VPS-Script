import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import access_transactions, backup, fail2ban, firewall, hy2, packages, ssh, wizard


class PendingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tx = self.root / "var/lib/vps-script/ssh-transactions" / ("a" * 24)

    def test_empty_query_does_not_create_state(self):
        self.assertEqual(access_transactions.pending(self.root), [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_only_valid_terminal_states_unblock(self):
        self.tx.mkdir(parents=True, mode=0o700)
        self.assertEqual(len(access_transactions.pending(self.root)), 1)
        for terminal in ("confirmed", "rolled-back", "expired"):
            marker = self.tx / terminal
            marker.write_text("1\n")
            self.assertEqual(access_transactions.pending(self.root), [])
            marker.unlink()
        (self.tx / "expired").write_text("1\n")
        (self.tx / "apply-started").write_text("1\n")
        with self.assertRaisesRegex(backup.BackupFailure, "未结束"):
            access_transactions.require_settled(self.root)

    def test_permission_denied_is_not_an_empty_transaction_list(self):
        original = Path.lstat
        def denied(path):
            if path == self.tx.parent:
                raise PermissionError("private root transaction directory")
            return original(path)
        with patch.object(Path, "lstat", denied):
            with self.assertRaises(PermissionError):
                access_transactions.pending(self.root)
            with self.assertRaisesRegex(backup.BackupFailure, "无法确认"):
                access_transactions.require_settled(self.root)

    def test_symlink_or_writable_marker_does_not_prove_confirmation(self):
        self.tx.mkdir(parents=True, mode=0o700)
        other = self.root / "other"
        other.write_text("1")
        marker = self.tx / "confirmed"
        marker.symlink_to(other)
        with self.assertRaises(backup.BackupFailure):
            access_transactions.require_settled(self.root)
        marker.unlink()
        marker.write_text("1")
        marker.chmod(0o666)
        with self.assertRaises(backup.BackupFailure):
            access_transactions.require_settled(self.root)

    def test_cross_module_gate_precedes_backup_and_operation(self):
        self.tx.mkdir(parents=True, mode=0o700)
        adapter, operation = Mock(), Mock()
        for module in ("ssh", "ufw", "fail2ban", "hy2"):
            with self.assertRaisesRegex(backup.BackupFailure, "未结束"):
                backup.track(module, "test", operation, adapter=adapter, store=backup.Store(self.root))
        operation.assert_not_called()
        adapter.capture.assert_not_called()


class PartialResultTest(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(packages, "preflight", return_value=None))
        self.stack.enter_context(patch("builtins.input", return_value="YES"))
        self.stack.enter_context(patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 12345 192.0.2.2 22", "SUDO_USER": "root"}))

    def test_ssh_ancillary_failure_before_record_reaches_wizard(self):
        with patch.object(backup, "track", return_value="primary completed"), \
                patch.object(fail2ban, "refresh_ports", return_value=1):
            code = ssh.change(new_port=2222, experimental=True)
        self.assertEqual(code, 1)
        step = wizard.Step("test", "SSH", "ssh", lambda: None, ("ssh", "add-port"), "")
        label, problem = wizard.classify(step, code, [{"module": "ssh", "action": "add-port", "state": "completed"}])
        self.assertTrue(problem)
        self.assertIn("部分执行", label)

    def test_hy2_ufw_failure_before_record_returns_partial(self):
        manager = Mock()
        manager.command.return_value = "/usr/sbin/ufw"
        manager.status.return_value = "active"
        def tracked(module, action, operation, **kwargs):
            if module == "hy2":
                return "primary completed"
            raise backup.BackupFailure("snapshot unreadable")
        with patch.object(Path, "is_dir", return_value=True), \
                patch.object(backup, "track", side_effect=tracked), \
                patch.object(firewall, "FirewallManager", return_value=manager):
            self.assertEqual(hy2.change(hy2.HopSpec("eth0", 20000, 20100, 443, ("ip",)),
                                       allow_firewall=True, experimental=True), 1)

    def test_restore_ssh_refresh_failure_preserves_primary_and_returns_partial(self):
        identifier = "a" * 32
        record = {"module": "ssh", "restore_supported": True, "state": "completed"}
        with patch.object(backup, "Store") as store, \
                patch.object(backup, "public_record", return_value={}), \
                patch.object(backup, "render_history", return_value="record"), \
                patch.object(backup, "restore_record", return_value="restored") as restore, \
                patch.object(fail2ban, "refresh_ports", return_value=1), \
                patch("builtins.input", return_value="RESTORE " + identifier):
            store.return_value.read.return_value = record
            self.assertEqual(backup.restore(identifier, experimental=True), 1)
            restore.assert_called_once_with(identifier)
