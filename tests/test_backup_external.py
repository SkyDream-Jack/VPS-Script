"""External mutations must be recorded without promising automatic recovery.

All downloads/processes are mocked; temporary scripts use private fixtures.
The record storage engine has its own filesystem/security tests.
"""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import backup, external, packages, panel


class ExternalBackupIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="vps-external-test-"))
        self.store = backup.Store(root=Path(directory))
        self.real_track = backup.track
        original_temporary = tempfile.NamedTemporaryFile

        def local_temporary(*args, **kwargs):
            kwargs["dir"] = directory
            return original_temporary(*args, **kwargs)

        self.stack.enter_context(patch.object(tempfile, "NamedTemporaryFile", side_effect=local_temporary))
        self.stack.enter_context(patch.object(packages, "preflight", return_value=None))
        self.stack.enter_context(patch.object(packages, "source_origins", return_value=((), False)))
        self.stack.enter_context(patch.object(panel, "check_environment", return_value=None))
        self.stack.enter_context(patch.object(panel, "download_installer", return_value=b"harmless fixture"))
        self.stack.enter_context(patch.object(external, "download", return_value=(external.SPECS["nq"], b"harmless fixture", "a" * 64)))
        self.run = self.stack.enter_context(patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)))
        self.confirm = self.stack.enter_context(patch.object(backup, "confirm_external_snapshot", return_value=True))
        self.track = self.stack.enter_context(patch.object(backup, "track", side_effect=self.execute_recorded))

    @staticmethod
    def execute_recorded(module, action, operation, **kwargs):
        try:
            return operation()
        except Exception as exc:
            raise backup.BackupFailure("operation failed after recording") from exc

    def invoke(self, module):
        if module == "packages":
            with patch("builtins.input", return_value="YES"):
                return packages.run_action("upgrade", experimental=True)
        if module == "panel":
            with patch("builtins.input", side_effect=["YES", "YES"]):
                return panel.install(experimental=True)
        with patch("builtins.input", return_value="RUN"):
            return external.run("nq", experimental=True)

    def test_declined_external_snapshot_prevents_mutation_and_record(self):
        for module in ("packages", "panel", "external"):
            with self.subTest(module=module):
                self.track.reset_mock()
                self.run.reset_mock()
                self.confirm.return_value = False
                self.assertEqual(self.invoke(module), 0)
                self.track.assert_not_called()
                # APT simulation precedes confirmation; no real command follows.
                self.assertEqual(self.run.call_count, 1 if module == "packages" else 0)
                if module == "packages":
                    self.assertIn("--simulate", self.run.call_args.args[0])

    def test_record_failure_blocks_all_external_mutations(self):
        self.track.side_effect = backup.BackupFailure("cannot prepare persistent record")
        for module in ("packages", "panel", "external"):
            with self.subTest(module=module):
                self.run.reset_mock()
                self.assertEqual(self.invoke(module), 1)
                self.assertEqual(self.run.call_count, 1 if module == "packages" else 0)

    def test_external_records_cannot_offer_automatic_restore(self):
        for module in ("packages", "panel", "external"):
            with self.subTest(module=module):
                self.track.reset_mock()
                self.assertEqual(self.invoke(module), 0)
                args, kwargs = self.track.call_args
                self.assertEqual(args[0], module)
                self.assertFalse(kwargs["restore_supported"])
                self.assertEqual(kwargs["details"]["external_snapshot"], "user_declared_unverified")
                self.assertIn("limitation", kwargs["details"])
                self.assertNotIn("stdout", kwargs["details"])
                self.assertNotIn("environment", kwargs["details"])

    def test_index_update_is_recorded_without_requiring_provider_snapshot(self):
        with patch("builtins.input", return_value="YES"):
            self.assertEqual(packages.run_action("update", experimental=True), 0)
        self.confirm.assert_not_called()
        self.assertFalse(self.track.call_args.kwargs["restore_supported"])
        self.assertEqual(self.track.call_args.kwargs["details"]["external_snapshot"], "not_required_for_index_update")
        self.assertEqual(self.run.call_count, 1)

    def test_declining_original_confirmation_never_asks_for_snapshot(self):
        for module in ("packages", "panel", "external"):
            with self.subTest(module=module):
                self.confirm.reset_mock()
                self.track.reset_mock()
                with patch("builtins.input", return_value="no"):
                    action = (lambda: packages.run_action("upgrade", experimental=True)) if module == "packages" else (
                        lambda: panel.install(experimental=True)) if module == "panel" else (
                        lambda: external.run("nq", experimental=True))
                    self.assertEqual(action(), 0)
                self.confirm.assert_not_called()
                self.track.assert_not_called()

    def test_nonzero_commands_are_failed_records_and_keep_exit_code(self):
        for module in ("packages", "panel", "external"):
            with self.subTest(module=module):
                # The package simulation succeeds before the real command fails.
                results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 17)] if module == "packages" else [subprocess.CompletedProcess([], 17)]
                self.run.side_effect = results
                self.assertEqual(self.invoke(module), 17)
        self.run.side_effect = None
        self.assertNotIn("外部测试退出码为 0", self.output.getvalue())

    def test_finish_record_failure_does_not_claim_mutation_never_started(self):
        def fail_after_execution(module, action, operation, **kwargs):
            operation()
            raise backup.BackupFailure("command ran; final record failed")
        self.track.side_effect = fail_after_execution
        self.assertEqual(self.invoke("external"), 1)
        self.run.assert_called_once()
        text = self.output.getvalue()
        self.assertIn("记录未完成", text)
        self.assertNotIn("未执行", text)
        self.assertNotIn("退出码为 0", text)

    def test_real_store_records_external_operations_without_restorable_backup(self):
        self.track.side_effect = lambda module, action, operation, **kwargs: self.real_track(
            module, action, operation, store=self.store, **kwargs)
        for module in ("packages", "panel", "external"):
            self.assertEqual(self.invoke(module), 0)
        records = backup.history(store=self.store)["records"]
        self.assertEqual(len(records), 3)
        self.assertEqual({record["module"] for record in records}, {"packages", "panel", "external"})
        for record in records:
            self.assertEqual(record["state"], "completed")
            self.assertFalse(record["restore_supported"])
            stored = self.store.read(record["id"])
            self.assertEqual(stored["details"]["external_snapshot"], "user_declared_unverified")
            self.assertEqual(stored["before"], {"kind": "external_snapshot_required"})
            with self.assertRaises(backup.BackupFailure):
                backup.restore_record(record["id"], store=self.store)

    def test_real_store_keeps_failed_external_execution_record(self):
        self.track.side_effect = lambda module, action, operation, **kwargs: self.real_track(
            module, action, operation, store=self.store, **kwargs)
        self.run.return_value = subprocess.CompletedProcess([], 19)
        self.assertEqual(self.invoke("external"), 19)
        records = backup.history(store=self.store)["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "failed")
        self.assertFalse(records[0]["restore_supported"])


if __name__ == "__main__":
    unittest.main()
