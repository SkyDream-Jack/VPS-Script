"""Journal tests use private temporary roots and fake adapters; no VPS commands."""

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import backup, cli


class Adapter:
    scope = "test configuration"
    limitations = "test only"

    def __init__(self):
        self.value = {"configuration": "sensitive-before"}
        self.restores = 0

    def capture(self):
        return copy.deepcopy(self.value)

    def recovery_reason(self, before, after):
        return None

    def restore(self, before, after):
        if self.capture() != after:
            raise backup.BackupFailure("external edit")
        self.restores += 1
        self.value = copy.deepcopy(before)
        return "restored"


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = backup.Store(self.root)
        self.adapter = Adapter()
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def change(self):
        self.adapter.value["configuration"] = "sensitive-after"
        return "command completed"

    def track(self, operation=None, **kwargs):
        return backup.track("timezone", "set", operation or self.change, adapter=self.adapter,
                            store=self.store, **kwargs)

    def only(self):
        rows = self.store.list()
        self.assertEqual(len(rows), 1)
        return self.store.read(rows[0]["id"])

    def test_readonly_empty_history_creates_nothing_and_collects_nothing(self):
        with patch.object(backup, "get_adapter", side_effect=AssertionError("read invoked adapter")):
            self.assertEqual(backup.history(store=self.store)["records"], [])
        self.assertFalse(self.store.directory.exists())

    def test_durable_before_precedes_operation_and_success_is_recorded(self):
        def operation():
            record = self.only()
            self.assertEqual(record["state"], "running")
            self.assertEqual(record["before"], self.adapter.capture())
            self.assertIsNone(record["after"])
            return self.change()
        self.assertEqual(self.track(operation), "command completed")
        record = self.only()
        self.assertEqual(record["state"], "completed")
        self.assertTrue(record["restore_supported"])
        self.assertEqual(record["before"]["configuration"], "sensitive-before")
        self.assertEqual(record["after"]["configuration"], "sensitive-after")
        self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        path = self.store._path(record["id"]) / "record.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_before_write_failure_blocks_operation(self):
        operation = Mock()
        with patch.object(self.store, "_write", side_effect=OSError("disk full")), \
                self.assertRaises(backup.BackupFailure):
            self.track(operation)
        operation.assert_not_called()
        self.assertEqual(self.adapter.capture()["configuration"], "sensitive-before")

    def test_new_storage_ancestors_are_synced_before_operation(self):
        with patch.object(backup, "_fsync_directory", wraps=backup._fsync_directory) as sync:
            self.track()
        synced = {entry.args[0] for entry in sync.call_args_list}
        for parent in (self.root, self.root / "var", self.root / "var/lib", self.root / "var/lib/vps-script"):
            self.assertIn(parent, synced)

    def test_storage_directory_sync_failure_blocks_operation(self):
        operation = Mock()
        with patch.object(backup, "_fsync_directory", side_effect=OSError("sync failed")), \
                self.assertRaises(backup.BackupFailure):
            self.track(operation)
        operation.assert_not_called()

    def test_running_write_failure_leaves_prepared_backup_and_blocks_operation(self):
        original = self.store._write
        count = 0
        def write(record, **kwargs):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("disk full")
            return original(record, **kwargs)
        operation = Mock()
        with patch.object(self.store, "_write", side_effect=write), self.assertRaises(backup.BackupFailure):
            self.track(operation)
        operation.assert_not_called()
        self.assertEqual(self.only()["state"], "prepared")

    def test_completion_write_failure_does_not_report_unexecuted(self):
        original = self.store._write
        count = 0
        def write(record, **kwargs):
            nonlocal count
            count += 1
            if count == 3:
                raise OSError("disk full")
            return original(record, **kwargs)
        operation = Mock(side_effect=self.change)
        with patch.object(self.store, "_write", side_effect=write), \
                self.assertRaisesRegex(backup.BackupFailure, "操作已执行.*不要重复执行"):
            self.track(operation)
        operation.assert_called_once_with()
        self.assertEqual(self.only()["state"], "running")

    def test_failed_operation_preserves_both_snapshots_but_disables_automatic_restore(self):
        def operation():
            self.change()
            raise RuntimeError("credential-output-must-not-be-saved")
        with self.assertRaises(backup.BackupFailure):
            self.track(operation)
        record = self.only()
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["error_type"], "RuntimeError")
        self.assertFalse(record["restore_supported"])
        self.assertNotIn("credential-output", json.dumps(record))
        with self.assertRaises(backup.BackupFailure):
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.adapter.restores, 0)

    def test_nonzero_return_is_not_recorded_as_success(self):
        with self.assertRaises(backup.BackupFailure):
            self.track(lambda: 7)
        self.assertEqual(self.only()["state"], "failed")

    def test_interruption_keeps_material_without_swallowing_interrupt(self):
        def operation():
            self.change()
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.track(operation)
        self.assertEqual(self.only()["state"], "interrupted")
        self.assertFalse(self.only()["restore_supported"])

    def test_after_capture_failure_keeps_before_and_reports_failure(self):
        initial = self.adapter.capture()
        with patch.object(self.adapter, "capture", side_effect=[initial, initial, OSError("offline"), OSError("offline")]), \
                self.assertRaises(backup.BackupFailure):
            self.track()
        record = self.only()
        self.assertEqual(record["before"], initial)
        self.assertIsNone(record["after"])
        self.assertEqual(record["state"], "failed")

    def test_state_drift_while_saving_backup_blocks_operation(self):
        original = self.store._write
        def write(record, **kwargs):
            original(record, **kwargs)
            if record["state"] == "running":
                self.adapter.value["configuration"] = "manual-change-during-journal-write"
        operation = Mock()
        with patch.object(self.store, "_write", side_effect=write), \
                self.assertRaisesRegex(backup.BackupFailure, "备份期间"):
            self.track(operation)
        operation.assert_not_called()
        record = self.only()
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["before"]["configuration"], "sensitive-before")

    def test_noop_is_not_a_successful_restorable_change(self):
        self.track(lambda: "already set")
        record = self.only()
        self.assertEqual(record["state"], "no_change")
        self.assertFalse(record["restore_supported"])

    def test_manual_only_adapter_record_has_no_fake_backup_promise(self):
        result = backup.track("packages", "upgrade", lambda: 0, store=self.store,
                              restore_supported=False, details={"external_snapshot": "user_declared_unverified"})
        self.assertEqual(result, 0)
        record = self.only()
        self.assertEqual(record["state"], "completed")
        self.assertFalse(record["restore_supported"])
        self.assertIn("不包含", record["scope"])

    def test_audit_only_action_does_not_require_recovery_validation(self):
        with patch.object(self.adapter, "recovery_reason", side_effect=AssertionError("not a recovery")):
            self.track(restore_supported=False)
        self.assertEqual(self.only()["state"], "completed")
        self.assertFalse(self.only()["restore_supported"])

    def test_restore_creates_new_record_and_rejects_repeated_source_restore(self):
        self.track()
        source = self.only()
        self.assertEqual(backup.restore_record(source["id"], store=self.store, adapter=self.adapter), "restored")
        current = self.store.read(source["id"])
        self.assertEqual(current["state"], "restored")
        restored = self.store.read(current["restored_by"])
        self.assertEqual(restored["restores"], source["id"])
        self.assertEqual(restored["before"], source["after"])
        self.assertEqual(restored["after"], source["before"])
        with self.assertRaises(backup.BackupFailure):
            backup.restore_record(source["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.adapter.restores, 1)

    def test_external_change_blocks_restore_before_creating_new_record(self):
        self.track()
        source = self.only()
        self.adapter.value["configuration"] = "later-manual-edit"
        with self.assertRaisesRegex(backup.BackupFailure, "后续变更"):
            backup.restore_record(source["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.adapter.restores, 0)
        self.assertEqual(len(self.store.list()), 1)

    def test_restore_failure_keeps_new_failure_and_does_not_mark_source_restored(self):
        self.track()
        source = self.only()
        with patch.object(self.adapter, "restore", side_effect=RuntimeError("restore failure")), \
                self.assertRaises(backup.BackupFailure):
            backup.restore_record(source["id"], store=self.store, adapter=self.adapter)
        self.assertEqual(self.store.read(source["id"])["state"], "completed")
        rows = self.store.list()
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["state"] for row in rows}, {"completed", "failed"})

    def test_capacity_blocks_next_mutation_without_deleting_any_record(self):
        self.track()
        operation = Mock()
        with patch.object(backup, "MAX_RECORDS", 1), self.assertRaisesRegex(backup.BackupFailure, "容量限制"):
            self.track(operation)
        operation.assert_not_called()
        self.assertEqual(len(self.store.list()), 1)

    def test_concurrent_writer_is_refused(self):
        operation = Mock()
        with self.store.locked(), self.assertRaisesRegex(backup.BackupFailure, "另一个"):
            self.track(operation)
        operation.assert_not_called()

    def test_history_redacts_all_snapshot_contents(self):
        self.track()
        source = self.only()
        for identifier in (None, source["id"]):
            payload = backup.history(identifier, store=self.store)
            output = json.dumps(payload) + backup.render_history(payload)
            self.assertNotIn("sensitive-before", output)
            self.assertNotIn("sensitive-after", output)
            self.assertNotIn('"configuration"', output)
        with patch.object(backup, "get_adapter", side_effect=AssertionError("collector called")):
            backup.history(source["id"], store=self.store)

    def test_traversal_and_symlink_record_are_rejected(self):
        for value in ("../x", "/tmp/x", "A" * 32, "a" * 31, "a" * 33):
            with self.subTest(value=value), self.assertRaises(backup.BackupFailure):
                self.store.read(value)
        self.track()
        source = self.only()
        path = self.store._path(source["id"]) / "record.json"
        saved = path.read_bytes()
        path.unlink()
        outside = self.root / "external"
        outside.write_bytes(saved)
        outside.chmod(0o600)
        path.symlink_to(outside)
        with self.assertRaises(backup.BackupFailure):
            self.store.read(source["id"])
        self.assertEqual(self.store.list()[0]["state"], "invalid")

    def test_hash_corruption_and_unknown_schema_are_not_restored(self):
        self.track()
        source = self.only()
        path = self.store._path(source["id"]) / "record.json"
        original = path.read_bytes()
        envelope = json.loads(original)
        envelope["record"]["before"]["configuration"] = "tampered"
        path.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(backup.BackupFailure, "摘要"):
            self.store.read(source["id"])
        envelope = json.loads(original)
        envelope["record"]["schema"] = 99
        envelope["sha256"] = hashlib.sha256(backup._json(envelope["record"])).hexdigest()
        path.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(backup.BackupFailure, "schema"):
            self.store.read(source["id"])

    def test_unsafe_directory_and_record_permissions_are_rejected(self):
        self.track()
        source = self.only()
        directory = self.store._path(source["id"])
        (directory / "record.json").chmod(0o644)
        with self.assertRaises(backup.BackupFailure):
            self.store.read(source["id"])
        self.store.directory.chmod(0o777)
        with self.assertRaises(backup.BackupFailure):
            self.store.list()

    def test_explicit_delete_preserves_system_but_refuses_incomplete_records(self):
        self.track()
        source = self.only()
        self.store.delete(source["id"])
        self.assertEqual(self.store.list(), [])
        self.assertEqual(self.adapter.value["configuration"], "sensitive-after")
        self.adapter.value["configuration"] = "before"
        with self.assertRaises(backup.BackupFailure):
            self.track(lambda: 1)
        source = self.only()
        with self.assertRaisesRegex(backup.BackupFailure, "不能通过菜单删除"):
            self.store.delete(source["id"])

    def test_unsupported_metadata_is_rejected_before_operation(self):
        operation = Mock()
        with self.assertRaises(backup.BackupFailure):
            self.track(operation, details={"environment": "secret"})
        operation.assert_not_called()

    def test_interactive_restore_requires_exact_record_confirmation(self):
        self.track()
        identifier = self.only()["id"]
        with patch.object(backup, "Store", return_value=self.store), \
                patch.object(backup, "get_adapter", return_value=self.adapter), \
                patch.object(cli.packages, "preflight", return_value=None):
            with patch("builtins.input", return_value="YES"):
                self.assertEqual(backup.restore(identifier, experimental=True), 0)
            self.assertEqual(self.adapter.restores, 0)
            self.assertEqual(self.store.read(identifier)["state"], "completed")
            with patch("builtins.input", return_value="RESTORE " + identifier):
                self.assertEqual(backup.restore(identifier, experimental=True), 0)
        self.assertEqual(self.adapter.restores, 1)
        self.assertEqual(self.store.read(identifier)["state"], "restored")

    def test_interactive_delete_cancellation_preserves_backup(self):
        self.track()
        identifier = self.only()["id"]
        with patch.object(backup, "Store", return_value=self.store), \
                patch.object(cli.packages, "preflight", return_value=None), \
                patch("builtins.input", return_value="DELETE"):
            self.assertEqual(backup.delete(identifier, experimental=True), 0)
        self.assertEqual(len(self.store.list()), 1)

    def test_snapshot_declaration_requires_exact_word_and_does_no_probe(self):
        with patch("builtins.input", return_value="YES"):
            self.assertFalse(backup.confirm_external_snapshot())
        with patch("builtins.input", return_value="SNAPSHOT"):
            self.assertTrue(backup.confirm_external_snapshot())
        with patch("builtins.input", side_effect=EOFError()):
            self.assertFalse(backup.confirm_external_snapshot())


class FileSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc/app").mkdir(parents=True)
        self.file = self.root / "etc/app/config"
        self.file.write_bytes(b"original\n")
        self.file.chmod(0o640)
        self.paths = ("etc/app/config", "etc/app/new")

    def test_restore_bytes_permissions_and_original_absence(self):
        before = backup.snapshot_files(self.root, self.paths)
        self.file.write_bytes(b"changed\n")
        self.file.chmod(0o600)
        (self.root / self.paths[1]).write_bytes(b"new")
        after = backup.snapshot_files(self.root, self.paths)
        backup.restore_files(self.root, before, after, self.paths)
        self.assertEqual(self.file.read_bytes(), b"original\n")
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.root / self.paths[1]).exists())
        self.assertEqual(backup.snapshot_files(self.root, self.paths), before)

    def test_external_change_prevents_all_restoration_writes(self):
        before = backup.snapshot_files(self.root, self.paths)
        self.file.write_bytes(b"changed")
        after = backup.snapshot_files(self.root, self.paths)
        (self.root / self.paths[1]).write_bytes(b"manual")
        with self.assertRaisesRegex(backup.BackupFailure, "后续操作"):
            backup.restore_files(self.root, before, after, self.paths)
        self.assertEqual(self.file.read_bytes(), b"changed")

    def test_fixed_path_allowlist_cannot_be_expanded_by_record(self):
        before = backup.snapshot_files(self.root, self.paths)
        before["etc/evil"] = {"exists": False}
        with self.assertRaises(backup.BackupFailure):
            backup.restore_files(self.root, before, before, self.paths)
        for path in ("../etc/passwd", "/etc/passwd", "etc//app", "etc/./app", "etc/../app"):
            with self.subTest(path=path), self.assertRaises(backup.BackupFailure):
                backup.snapshot_files(self.root, (path,))

    def test_corrupt_contents_or_metadata_rejected_before_writing(self):
        original = backup.snapshot_files(self.root, self.paths)
        for mutate in (lambda data: data.update(data=base64.b64encode(b"forged").decode()),
                       lambda data: data.update(mode=0o7777), lambda data: data.update(uid=-1)):
            before = copy.deepcopy(original)
            mutate(before[self.paths[0]])
            with self.assertRaises(backup.BackupFailure):
                backup.restore_files(self.root, before, original, self.paths)
        self.assertEqual(self.file.read_bytes(), b"original\n")

    def test_symlinks_hardlinks_and_unsafe_parent_are_rejected(self):
        self.file.unlink()
        target = self.root / "target"
        target.write_text("protected")
        self.file.symlink_to(target)
        with self.assertRaises(backup.BackupFailure):
            backup.snapshot_files(self.root, self.paths)
        self.file.unlink()
        os.link(target, self.file)
        with self.assertRaises(backup.BackupFailure):
            backup.snapshot_files(self.root, self.paths)
        self.file.unlink()
        self.file.write_text("new")
        self.file.parent.chmod(0o777)
        with self.assertRaises(backup.BackupFailure):
            backup.snapshot_files(self.root, self.paths)

    def test_size_limit_refuses_backup(self):
        self.file.write_bytes(b"a" * (backup.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(backup.BackupFailure, "大小限制"):
            backup.snapshot_files(self.root, self.paths)


class BackupCLITest(unittest.TestCase):
    def test_demo_history_and_restore_never_read_store(self):
        with patch.object(backup, "Store", side_effect=AssertionError("host accessed")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["history", "--demo", "--json"]), 0)
            self.assertTrue(json.loads(output.getvalue())["demo"])
        with patch.object(backup, "Store", side_effect=AssertionError("host accessed")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["restore", "a" * 32, "--demo", "--experimental"]), 0)

    def test_readonly_and_demo_menu_block_restore_delete_before_record_selection(self):
        for demo, experimental in ((False, False), (True, False), (True, True)):
            with self.subTest(demo=demo, experimental=experimental), \
                    patch.object(cli, "_choose_record", side_effect=AssertionError("record prompt")), \
                    patch("builtins.input", side_effect=["3", "4", "0"]), \
                    contextlib.redirect_stdout(io.StringIO()):
                cli.backup_menu(demo=demo, experimental=experimental)

    def test_history_json_is_clean_and_uses_only_readonly_api(self):
        payload = {"schema": 1, "records": [], "storage": "/example"}
        with patch.object(cli.platform, "system", return_value="Linux"), \
                patch.object(backup, "history", return_value=payload) as query, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["history", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue()), payload)
        query.assert_called_once_with(None)

    def test_restore_preflight_failure_does_not_read_or_mutate(self):
        with patch.object(cli.packages, "preflight", return_value="只读模式"), \
                patch.object(backup, "Store", side_effect=AssertionError("unexpected store")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(backup.restore("a" * 32), 2)

    def test_invalid_record_paths_are_cli_errors(self):
        for args in (["restore"], ["restore", "../x"], ["history", "/etc/passwd"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                cli.main(args)
            self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
