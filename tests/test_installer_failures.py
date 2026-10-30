"""Exercise the actual embedded transaction using only private fixture paths.

The Bash platform/root/TTY gates remain covered by test_installer.py. These tests
load the exact Python transaction from install-local.sh, without copying its
implementation, bypassing host gates, invoking sudo or touching /opt.
"""

import contextlib
import fcntl
import io
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
MARKER = "INSTALL_TRANSACTION_PY"


def load_transaction():
    text = (PROJECT / "install-local.sh").read_text()
    code = text.split("<<'" + MARKER + "'\n", 1)[1].split("\n" + MARKER, 1)[0]
    module = types.ModuleType("installer_transaction_fixture")
    exec(compile(code, str(PROJECT / "install-local.sh") + "::<transaction>", "exec"), module.__dict__)
    return module


class InstallerTransactionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vps-installer-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "vps-admin").write_text("new program")
        (self.source / "README.md").write_text("new documentation")
        self.destination = self.root / "opt" / "vps-script"
        self.destination.parent.mkdir()
        self.launcher = self.root / "bin" / "vps-script"
        self.launcher.parent.mkdir()
        self.module = load_transaction()
        self.output = io.StringIO()
        # Keep stdout local while the real transaction prints its result.
        self.stdout_context = contextlib.redirect_stdout(self.output)
        self.stdout_context.__enter__()
        self.addCleanup(self.stdout_context.__exit__, None, None, None)
        self.stderr_context = contextlib.redirect_stderr(self.output)
        self.stderr_context.__enter__()
        self.addCleanup(self.stderr_context.__exit__, None, None, None)

    def installed(self):
        self.destination.mkdir()
        (self.destination / "vps-admin").write_text("old program")
        (self.destination / "custom-state").write_text("must survive failed upgrade")
        self.launcher.write_text("old launcher")
        self.launcher.chmod(0o751)

    def run_install(self, upgrade=True):
        self.module.install_transaction(
            self.source, self.destination, self.launcher, upgrade,
            ["vps-admin", "README.md"],
        )

    def assert_original(self):
        self.assertEqual((self.destination / "vps-admin").read_text(), "old program")
        self.assertEqual((self.destination / "custom-state").read_text(), "must survive failed upgrade")
        self.assertEqual(self.launcher.read_text(), "old launcher")
        self.assertEqual(stat.S_IMODE(self.launcher.stat().st_mode), 0o751)

    def assert_no_transaction_debris(self):
        self.assertEqual(list(self.destination.parent.glob(".vps-script-transaction.*")), [])
        self.assertEqual(list(self.launcher.parent.glob(".vps-script-*")), [])

    def test_fresh_install_and_upgrade_use_fixture_paths(self):
        self.run_install(upgrade=False)
        self.assertEqual((self.destination / "vps-admin").read_text(), "new program")
        self.assertEqual(stat.S_IMODE((self.destination / "vps-admin").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.launcher.stat().st_mode), 0o755)
        (self.source / "vps-admin").write_text("second program")
        self.run_install()
        self.assertEqual((self.destination / "vps-admin").read_text(), "second program")
        self.assert_no_transaction_debris()

    def test_launcher_preparation_failures_leave_old_installation_unchanged(self):
        self.installed()
        failures = (
            (self.module.tempfile, "mkstemp"),
            (self.module.os, "fsync"),
            (self.module.os, "fchmod"),
        )
        for owner, method in failures:
            with self.subTest(method=method), patch.object(owner, method, side_effect=OSError("injected preparation failure")):
                with self.assertRaisesRegex(self.module.InstallFailure, "已恢复到操作前状态"):
                    self.run_install()
            self.assert_original()
            self.assert_no_transaction_debris()

    def test_program_publish_failure_restores_old_directory(self):
        self.installed()
        real_move = self.module.move_absent

        def fail_publish(source, target):
            if Path(source).name == "new":
                raise OSError("injected program publish failure")
            return real_move(source, target)

        with patch.object(self.module, "move_absent", side_effect=fail_publish):
            with self.assertRaisesRegex(self.module.InstallFailure, "已恢复到操作前状态"):
                self.run_install()
        self.assert_original()
        self.assert_no_transaction_debris()

    def test_launcher_publish_failure_moves_new_tree_aside_before_restore(self):
        self.installed()
        real_replace = os.replace

        def fail_publish(source, target):
            if Path(source).name.startswith(".vps-script-new."):
                raise OSError("injected launcher publish failure")
            return real_replace(source, target)

        with patch.object(self.module.os, "replace", side_effect=fail_publish):
            with self.assertRaisesRegex(self.module.InstallFailure, "已恢复到操作前状态"):
                self.run_install()
        self.assert_original()
        self.assert_no_transaction_debris()

    def test_interruption_after_launcher_replace_restores_original_launcher(self):
        self.installed()
        real_replace = os.replace

        def interrupt_after_publish(source, target):
            result = real_replace(source, target)
            if Path(source).name.startswith(".vps-script-new."):
                raise InterruptedError("injected signal after atomic replacement")
            return result

        with patch.object(self.module.os, "replace", side_effect=interrupt_after_publish):
            with self.assertRaisesRegex(self.module.InstallFailure, "已恢复到操作前状态"):
                self.run_install()
        self.assert_original()
        self.assert_no_transaction_debris()

    def test_fresh_install_launcher_failure_removes_only_new_program(self):
        with patch.object(self.module.os, "link", side_effect=OSError("injected link failure")):
            with self.assertRaises(self.module.InstallFailure):
                self.run_install(upgrade=False)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.launcher.exists())
        self.assert_no_transaction_debris()

    def test_conflicting_directory_is_preserved_with_recovery_backup(self):
        self.installed()
        real_move = self.module.move_absent

        def insert_external_directory(source, target):
            if Path(source).name == "new":
                self.destination.mkdir()
                (self.destination / "external").write_text("keep this")
            return real_move(source, target)

        with patch.object(self.module, "move_absent", side_effect=insert_external_directory):
            with self.assertRaisesRegex(self.module.InstallFailure, "自动恢复未完成") as error:
                self.run_install()
        self.assertNotIn("已恢复到操作前状态", str(error.exception))
        self.assertEqual((self.destination / "external").read_text(), "keep this")
        backups = list(self.destination.parent.glob(".vps-script-transaction.*/previous/vps-admin"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "old program")
        self.assertEqual(self.launcher.read_text(), "old launcher")

    def test_failed_restore_preserves_backup_and_does_not_claim_success(self):
        self.installed()
        real_move = self.module.move_absent

        def fail_restore(source, target):
            if Path(source).name == "previous":
                raise PermissionError("injected restore failure")
            return real_move(source, target)

        with patch.object(self.module, "move_absent", side_effect=fail_restore), \
             patch.object(self.module.os, "replace", side_effect=OSError("injected launcher failure")):
            with self.assertRaisesRegex(self.module.InstallFailure, "自动恢复未完成") as error:
                self.run_install()
        self.assertNotIn("已恢复到操作前状态", str(error.exception))
        backups = list(self.destination.parent.glob(".vps-script-transaction.*/previous/vps-admin"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "old program")
        self.assertEqual(self.launcher.read_text(), "old launcher")

    def test_unexpected_interruption_entering_rollback_keeps_only_old_backup(self):
        self.installed()
        real_move = self.module.move_absent
        text = (PROJECT / "install-local.sh").read_text()
        code = text.split("<<'" + MARKER + "'\n", 1)[1].split("\n" + MARKER, 1)[0]
        rollback_line = next(index for index, line in enumerate(code.splitlines(), 1)
                             if line.strip() == "errors = []")

        def fail_publish(source, target):
            if Path(source).name == "new":
                raise OSError("injected program publish failure")
            return real_move(source, target)

        def interrupt_at_rollback_entry(frame, event, argument):
            if (frame.f_code is self.module.perform_install.__code__
                    and event == "line" and frame.f_lineno == rollback_line):
                raise InterruptedError("injected exception outside restoration tries")
            return interrupt_at_rollback_entry

        old_trace = sys.gettrace()
        try:
            sys.settrace(interrupt_at_rollback_entry)
            with patch.object(self.module, "move_absent", side_effect=fail_publish):
                with self.assertRaisesRegex(InterruptedError, "outside restoration"):
                    self.run_install()
        finally:
            sys.settrace(old_trace)
        self.assertFalse(self.destination.exists())
        backups = list(self.destination.parent.glob(".vps-script-transaction.*/previous/vps-admin"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "old program")
        launcher_backups = list(self.launcher.parent.glob(".vps-script-previous.*"))
        self.assertEqual(len(launcher_backups), 1)
        self.assertEqual(launcher_backups[0].read_text(), "old launcher")
        self.assertIn("保留事务目录", self.output.getvalue())
        self.assertNotIn("已恢复到操作前状态", self.output.getvalue())

    def test_rollback_blocks_termination_signals_and_restores_original_mask(self):
        self.installed()
        real_move = self.module.move_absent
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        observed_masks = []

        def observe_restore(source, target):
            if Path(source).name == "previous":
                observed_masks.append(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
            return real_move(source, target)

        with patch.object(self.module, "move_absent", side_effect=observe_restore), \
             patch.object(self.module.os, "replace", side_effect=OSError("injected launcher failure")):
            with self.assertRaises(self.module.InstallFailure):
                self.run_install()
        self.assertEqual(len(observed_masks), 1)
        self.assertTrue({signal.SIGINT, signal.SIGTERM, signal.SIGHUP}.issubset(observed_masks[0]))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), original_mask)
        self.assert_original()

    def test_external_launcher_replacement_survives_failed_upgrade(self):
        self.installed()
        real_replace = os.replace

        def external_change(source, target):
            if Path(source).name.startswith(".vps-script-new."):
                other = self.launcher.parent / "external-launcher"
                other.write_text("external launcher")
                real_replace(other, self.launcher)
                raise OSError("external process changed launcher")
            return real_replace(source, target)

        with patch.object(self.module.os, "replace", side_effect=external_change):
            with self.assertRaisesRegex(self.module.InstallFailure, "自动恢复未完成"):
                self.run_install()
        self.assertEqual(self.launcher.read_text(), "external launcher")
        self.assertEqual((self.destination / "vps-admin").read_text(), "old program")
        backups = list(self.launcher.parent.glob(".vps-script-previous.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "old launcher")

    def test_atomic_move_does_not_replace_empty_directory_or_symlink(self):
        for kind in ("directory", "symlink"):
            with self.subTest(kind=kind):
                source = self.root / (kind + "-source")
                source.mkdir()
                target = self.root / (kind + "-target")
                if kind == "directory":
                    target.mkdir()
                else:
                    target.symlink_to(self.root / "missing")
                before = self.module.identity(target)
                with self.assertRaises(OSError):
                    self.module.move_absent(source, target)
                self.assertEqual(self.module.identity(target), before)
                self.assertTrue(source.is_dir())

    def test_held_install_lock_blocks_concurrent_upgrade_without_changes(self):
        self.installed()
        lock = self.destination.parent / ".vps-script.install.lock"
        with lock.open("wb") as file:
            lock.chmod(0o600)
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(self.module.InstallFailure, "另一个安装/升级"):
                self.run_install()
        self.assert_original()
        self.assert_no_transaction_debris()

    def test_symlink_lock_does_not_modify_its_target(self):
        self.installed()
        untouched = self.root / "unrelated"
        untouched.write_text("unchanged")
        (self.destination.parent / ".vps-script.install.lock").symlink_to(untouched)
        with self.assertRaises(OSError):
            self.run_install()
        self.assertEqual(untouched.read_text(), "unchanged")
        self.assert_original()


if __name__ == "__main__":
    unittest.main()
