"""History restoration tests; every runtime mutation uses fixture commands."""

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import backup, backup_network, bbr, common, hy2, swap, tuning
import test_bbr as bbr_fixture
import test_hy2 as hy2_fixture
import test_tuning as tuning_fixture


class _SwapCommands:
    header = "Filename Type Size Used Priority\n"

    def __init__(self, root):
        self.root = root
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        name = Path(args[0]).name
        path = self.root / "swapfile-vps-script"
        if name == "fallocate":
            with path.open("xb") as file:
                file.truncate(int(args[2][:-1]) * 1024 * 1024)
        elif name == "swapon":
            size = path.stat().st_size // 1024 - 4
            (self.root / "proc/swaps").write_text(self.header + f"{path} file {size} 0 -2\n")
        elif name == "swapoff":
            (self.root / "proc/swaps").write_text(self.header)
        elif name != "mkswap":
            raise AssertionError(f"unexpected fixture command: {args}")
        return subprocess.CompletedProcess(args, 0, "", "")


class _Hy2Commands(hy2_fixture.FakeNet):
    def __call__(self, args, **kwargs):
        if Path(args[0]).name == "systemctl" and args[-1] == hy2.UNIT_NAME:
            if args[1] == "is-active":
                return subprocess.CompletedProcess(args, 0 if self.active else 3, "active\n" if self.active else "inactive\n", "")
            if args[1] == "is-enabled":
                return subprocess.CompletedProcess(args, 0 if self.active else 1, "enabled\n" if self.active else "disabled\n", "")
        return super().__call__(args, **kwargs)


class BackupNetworkTest(unittest.TestCase):
    def bbr_case(self):
        case = bbr_fixture.BBRTest("test_apply_repeat_and_restore_preserves_other_files")
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case, backup_network.BBRAdapter(case.root, case.manager)

    def tuning_case(self):
        case = tuning_fixture.TuningTest("test_apply_repeat_restore_preserves_other_files")
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case, backup_network.TuningAdapter(case.root, case.manager)

    def hy2_case(self):
        case = hy2_fixture.Hy2Test("test_apply_and_remove_only_own_files")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.fake = _Hy2Commands()
        case.manager.runner = case.fake
        return case, backup_network.Hy2Adapter(case.root, case.manager)

    def swap_case(self, fstab="UUID=root / ext4 defaults 0 1\n"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name in ("etc", "proc", "run/lock"):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / "etc/fstab").write_text(fstab)
        (root / "proc/swaps").write_text(_SwapCommands.header)
        fake = _SwapCommands(root)
        manager = swap.SwapManager(root, fake)
        return manager, backup_network.SwapAdapter(root, manager)

    def test_bbr_apply_history_restores_runtime_and_files(self):
        case, adapter = self.bbr_case()
        before = adapter.capture()
        case.manager.apply(load_module=True)
        after = adapter.capture()
        self.assertIsNone(adapter.recovery_reason(before, after))
        adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)
        self.assertFalse(case.manager.modules.exists())

    def test_bbr_restore_history_reinstates_project_state(self):
        case, adapter = self.bbr_case()
        case.manager.apply(load_module=True)
        before = adapter.capture()
        case.manager.restore()
        after = adapter.capture()
        adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)
        self.assertEqual(case.manager.modules.read_bytes(), bbr.MODULES)

    def test_bbr_rejects_external_runtime_and_foreign_config_changes(self):
        case, adapter = self.bbr_case()
        before = adapter.capture()
        case.manager.apply()
        after = adapter.capture()
        original = len(case.runner.calls)
        case.manager._proc(bbr.QDISC).write_text("pfifo_fast\n")
        with self.assertRaisesRegex(backup.BackupFailure, "不一致"):
            adapter.restore(before, after)
        self.assertEqual(len(case.runner.calls), original)
        case.manager._proc(bbr.QDISC).write_text("fq\n")
        (case.root / "etc/sysctl.d/99-foreign.conf").write_text("net/core/default_qdisc = fq\n")
        with self.assertRaisesRegex(backup.BackupFailure, "不一致"):
            adapter.restore(before, after)
        self.assertEqual(len(case.runner.calls), original)

    def test_bbr_rejects_unknown_historical_keys(self):
        case, adapter = self.bbr_case()
        before = adapter.capture()
        case.manager.apply()
        after = adapter.capture()
        before["live"]["kernel.randomize_va_space"] = "0"
        writes = len(case.runner.calls)
        with self.assertRaisesRegex(backup.BackupFailure, "历史运行值"):
            adapter.restore(before, after)
        self.assertEqual(len(case.runner.calls), writes)

    def test_restore_rechecks_foreign_sysctl_conflicts_before_writes(self):
        case, adapter = self.bbr_case()
        before = adapter.capture()
        case.manager.apply()
        after = adapter.capture()
        conflict = {"etc/sysctl.d/new.conf": [{"keys": [bbr.QDISC], "value": "fq"}]}
        with patch.object(adapter, "_current"), patch.object(backup_network, "_sysctl_context", return_value=conflict):
            writes = len(case.runner.calls)
            with self.assertRaisesRegex(backup.BackupFailure, "冲突"):
                adapter.restore(before, after)
            self.assertEqual(len(case.runner.calls), writes)

    def test_tuning_apply_history_restores_exact_values_without_recomputing(self):
        case, adapter = self.tuning_case()
        before = adapter.capture()
        case.manager.apply("buffer", bandwidth_mbps=500, rtt_ms=100)
        after = adapter.capture()
        adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)

    def test_tuning_restore_history_preserves_historical_buffer_target(self):
        case, adapter = self.tuning_case()
        case.manager.apply("buffer", bandwidth_mbps=500, rtt_ms=100)
        before = adapter.capture()
        case.manager.restore()
        after = adapter.capture()
        (case.root / "proc/meminfo").write_text("MemTotal: 2097152 kB\n")
        with patch.object(tuning, "target_values", side_effect=AssertionError("must not recalculate history")):
            adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)

    def test_tuning_external_file_change_blocks_recovery(self):
        case, adapter = self.tuning_case()
        before = adapter.capture()
        case.manager.apply("conservative")
        after = adapter.capture()
        case.manager.config.write_text("external edit\n")
        writes = len(case.fake.calls)
        with self.assertRaisesRegex(backup.BackupFailure, "不一致"):
            adapter.restore(before, after)
        self.assertFalse(any(call[1] == "-w" for call in case.fake.calls[writes:]))
        self.assertEqual(case.manager.config.read_text(), "external edit\n")

    def test_tuning_does_not_restore_unknown_or_unlisted_sysctl_values(self):
        case, adapter = self.tuning_case()
        before = adapter.capture()
        case.manager.apply("conservative")
        after = adapter.capture()
        before["live"]["net.core.somaxconn"] = None
        self.assertIn("可读性", adapter.recovery_reason(before, after))
        before["live"]["kernel.randomize_va_space"] = "0"
        self.assertIn("白名单", adapter.recovery_reason(before, after))

    def test_existing_tuning_key_read_failure_prevents_operation(self):
        case, adapter = self.tuning_case()
        key = "net.core.somaxconn"
        path = case.root / "proc/sys" / key.replace(".", "/")
        path.parent.mkdir(parents=True)
        path.write_text("128\n")
        original = case.manager._sysctl
        def unreadable(candidate):
            if candidate == key:
                raise tuning.TuningFailure("permission denied")
            return original(candidate)
        operation = Mock()
        with patch.object(case.manager, "_sysctl", side_effect=unreadable):
            with self.assertRaises(backup.BackupFailure):
                backup.track("tuning", "apply", operation, adapter=adapter, store=backup.Store(case.root))
        operation.assert_not_called()

    def test_absent_optional_tuning_key_is_preserved_as_unknown(self):
        case, adapter = self.tuning_case()
        key = "net.netfilter.nf_conntrack_max"
        del case.fake.values[key]
        self.assertIsNone(adapter.capture()["live"][key])

    def test_sysctl_context_accepts_trusted_distribution_alias(self):
        case, adapter = self.bbr_case()
        (case.root / "etc/sysctl.conf").write_text("net.core.default_qdisc = fq_codel\n")
        (case.root / "etc/sysctl.d/99-sysctl.conf").symlink_to("../sysctl.conf")
        context = adapter.capture()["context"]
        self.assertEqual(list(context), ["etc/sysctl.conf"])
        self.assertEqual(context["etc/sysctl.conf"][0]["keys"], [bbr.QDISC])

    def test_sysctl_context_never_blocks_on_fifo(self):
        case, adapter = self.bbr_case()
        target = case.root / "etc/sysctl.d/99-fifo.conf"
        os.mkfifo(target, 0o600)
        with patch.object(os, "open", wraps=os.open) as opened:
            with self.assertRaisesRegex(backup.BackupFailure, "普通文件"):
                adapter.capture()
        self.assertTrue(any(args[0][0] == target.resolve() and args[0][1] & os.O_NONBLOCK
                            for args in opened.call_args_list))

    def test_sysctl_context_rejects_external_alias_and_writable_target(self):
        case, adapter = self.bbr_case()
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        external = Path(outside.name) / "external.conf"
        external.write_text("net.core.default_qdisc = fq\n")
        alias = case.root / "etc/sysctl.d/99-other.conf"
        alias.symlink_to(external)
        with self.assertRaisesRegex(backup.BackupFailure, "超出"):
            adapter.capture()
        alias.unlink()
        alias.write_text("net.core.default_qdisc = fq\n")
        alias.chmod(0o666)
        with self.assertRaisesRegex(backup.BackupFailure, "其他用户"):
            adapter.capture()

    def test_sysctl_dev_null_mask_is_recorded_without_opening_device(self):
        case, adapter = self.bbr_case()
        device = case.root / "dev/null"
        device.parent.mkdir()
        device.touch()
        device = device.resolve()
        alias = case.root / "etc/sysctl.d/99-mask.conf"
        alias.symlink_to(device)
        original_lstat = Path.lstat
        fake_info = list(device.lstat())
        fake_info[0] = stat.S_IFCHR | 0o666
        def info(path, *args, **kwargs):
            return os.stat_result(fake_info) if path == device else original_lstat(path, *args, **kwargs)
        real_read = backup._read
        def guarded_read(path, *args, **kwargs):
            self.assertNotEqual(path, device)
            return real_read(path, *args, **kwargs)
        with patch.object(Path, "lstat", info), patch.object(backup, "_read", side_effect=guarded_read):
            self.assertEqual(adapter.capture()["context"], {"etc/sysctl.d/99-mask.conf": []})

    def test_hy2_apply_history_removes_only_project_configuration(self):
        case, adapter = self.hy2_case()
        before = adapter.capture()
        case.manager.apply(case.spec)
        after = adapter.capture()
        case.fake.counter = 500
        self.assertEqual(adapter.capture(), after)
        adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)

    def test_hy2_remove_history_rebuilds_and_validates_prior_configuration(self):
        case, adapter = self.hy2_case()
        case.manager.apply(case.spec)
        before = adapter.capture()
        case.manager.remove()
        after = adapter.capture()
        adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)

    def test_hy2_rebuild_still_checks_competing_nat_rules(self):
        case, adapter = self.hy2_case()
        case.manager.apply(case.spec)
        before = adapter.capture()
        case.manager.remove()
        after = adapter.capture()
        case.fake.extra_conflict = True
        with self.assertRaisesRegex(hy2.Hy2Failure, "其他 NAT"):
            adapter.restore(before, after)
        self.assertFalse(case.fake.active)

    def test_hy2_rebuild_rejects_changed_nft_executable_path(self):
        case, adapter = self.hy2_case()
        case.manager.apply(case.spec)
        before = adapter.capture()
        case.manager.remove()
        after = adapter.capture()
        original = case.manager.command
        def changed(name):
            return "/usr/bin/nft" if name == "nft" else original(name)
        with patch.object(case.manager, "command", side_effect=changed), \
             patch.object(case.manager, "apply") as applied:
            with self.assertRaisesRegex(backup.BackupFailure, "程序路径"):
                adapter.restore(before, after)
        applied.assert_not_called()
        self.assertFalse(case.manager.state.exists())

    def test_hy2_partial_or_modified_table_state_is_not_automatically_recoverable(self):
        case, adapter = self.hy2_case()
        before = adapter.capture()
        case.manager.apply(case.spec)
        after = adapter.capture()
        case.fake.rule_target = 444
        with self.assertRaisesRegex(backup.BackupFailure, "不一致"):
            adapter.restore(before, after)
        partial = copy.deepcopy(after)
        partial["service"] = "inactive"
        self.assertIsNotNone(adapter.recovery_reason(before, partial))

    def test_swap_create_history_preserves_fstab_without_newline(self):
        manager, adapter = self.swap_case("UUID=root / ext4 defaults 0 1 ")
        before = adapter.capture()
        manager.create(256)
        after = adapter.capture()
        adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)
        self.assertEqual(manager.fstab.read_text(), "UUID=root / ext4 defaults 0 1 ")

    def test_swap_remove_history_rebuilds_empty_swap_and_original_fstab_position(self):
        manager, adapter = self.swap_case()
        manager.create(256)
        manager.fstab.write_text(swap.FSTAB_LINE + "UUID=root / ext4 defaults 0 1\n")
        before = adapter.capture()
        manager.remove()
        after = adapter.capture()
        adapter.restore(before, after)
        self.assertEqual(adapter.capture(), before)
        self.assertEqual(manager.swap.stat().st_size, 256 * 1024 * 1024)

    def test_swap_snapshot_never_reads_swap_contents(self):
        manager, adapter = self.swap_case()
        manager.create(256)
        real_open = Path.open
        def no_swap_read(path, *args, **kwargs):
            if path == manager.swap:
                raise AssertionError("swap data must never be backed up")
            return real_open(path, *args, **kwargs)
        with patch.object(Path, "open", no_swap_read):
            snapshot = adapter.capture()
        self.assertNotIn("data", snapshot["swap"])
        self.assertEqual(set(snapshot["files"]), {"etc/fstab"})

    def test_swap_unknown_proc_state_and_external_fstab_change_stop_recovery(self):
        manager, adapter = self.swap_case()
        before = adapter.capture()
        manager.create(256)
        after = adapter.capture()
        manager.fstab.write_text(manager.fstab.read_text() + "UUID=data /data ext4 defaults 0 2\n")
        calls = len(manager.runner.calls)
        with self.assertRaisesRegex(backup.BackupFailure, "不一致"):
            adapter.restore(before, after)
        self.assertEqual(len(manager.runner.calls), calls)
        manager.proc_swaps.unlink()
        with self.assertRaises(OSError):
            adapter.capture()

    def test_swap_inactive_and_other_swap_states_are_manual_only(self):
        manager, adapter = self.swap_case()
        empty = adapter.capture()
        manager.create(256)
        current = adapter.capture()
        inactive = copy.deepcopy(current)
        inactive["active_bytes"] = None
        self.assertIsNotNone(adapter.recovery_reason(inactive, empty))
        other = copy.deepcopy(current)
        other["other_swaps"] = [["/dev/vdb", 1024 * 1024]]
        self.assertIsNotNone(adapter.recovery_reason(other, empty))

    def test_swap_empty_proc_file_is_not_assumed_to_mean_no_swap(self):
        manager, adapter = self.swap_case()
        manager.proc_swaps.write_text("")
        with self.assertRaisesRegex(backup.BackupFailure, "完整状态"):
            adapter.capture()

    def test_timezone_restore_uses_verified_effective_value(self):
        adapter = backup_network.TimezoneAdapter(Path("/fixture"))
        current = ["UTC"]
        def run(args, **kwargs):
            if args[1] == "show":
                return subprocess.CompletedProcess(args, 0, current[0] + "\n", "")
            if args[1] == "list-timezones":
                return subprocess.CompletedProcess(args, 0, "UTC\nAsia/Shanghai\n", "")
            if args[1] == "set-timezone":
                current[0] = args[2]
                return subprocess.CompletedProcess(args, 0, "", "")
            raise AssertionError(args)
        with patch.object(common.checks, "find_command", return_value="/usr/bin/timedatectl"), \
             patch.object(common, "_run", side_effect=run):
            before = adapter.capture()
            common.set_timezone("Asia/Shanghai")
            after = adapter.capture()
            adapter.restore(before, after)
            self.assertEqual(adapter.capture(), before)
            current[0] = "Europe/London"
            with self.assertRaisesRegex(backup.BackupFailure, "不一致"):
                adapter.restore(before, after)

    def test_timezone_does_not_fallback_to_configured_zone_on_command_failure(self):
        adapter = backup_network.TimezoneAdapter(Path("/fixture"))
        with patch.object(common.checks, "find_command", return_value="/usr/bin/timedatectl"), \
             patch.object(common, "_run", return_value=subprocess.CompletedProcess([], 1, "", "failed")), \
             patch.object(common, "timezone_status", side_effect=AssertionError("must not use fallback")):
            with self.assertRaisesRegex(backup.BackupFailure, "有效时区"):
                adapter.capture()

    def test_track_and_restore_record_cover_bbr_in_both_directions(self):
        case, adapter = self.bbr_case()
        store = backup.Store(case.root)
        before = adapter.capture()
        backup.track("bbr", "apply", case.manager.apply, adapter=adapter, store=store)
        applied = adapter.capture()
        records = store.list()
        self.assertEqual(len(records), 1)
        identifier = records[0]["id"]
        backup.restore_record(identifier, adapter=adapter, store=store)
        self.assertEqual(adapter.capture(), before)
        self.assertEqual(store.read(identifier)["state"], "restored")
        restored = store.read(identifier)["restored_by"]
        self.assertEqual(store.read(restored)["restores"], identifier)
        self.assertTrue(store.read(restored)["restore_supported"])
        self.assertEqual(len(store.list()), 2)
        backup.restore_record(restored, adapter=adapter, store=store)
        self.assertEqual(adapter.capture(), applied)
        self.assertEqual(len(store.list()), 3)


class BackupNetworkIntegrationTest(unittest.TestCase):
    def test_tuning_and_swap_apply_and_restore_use_separate_track_actions(self):
        for module, factory, kwargs, method, action in (
                (tuning, "TuningManager", {}, "apply", "apply"),
                (tuning, "TuningManager", {"restore": True}, "restore", "restore"),
                (swap, "SwapManager", {"size_mb": 256}, "create", "create"),
                (swap, "SwapManager", {"remove": True}, "remove", "remove")):
            with self.subTest(module=module.__name__, action=action):
                manager = Mock()
                manager.status.return_value = {"fstab_managed": True}
                def tracked(name, actual_action, operation, **options):
                    self.assertEqual((name, actual_action), (module.__name__.split(".")[-1], action))
                    getattr(manager, method).assert_not_called()
                    return operation()
                with patch.object(module.packages, "preflight", return_value=None), \
                     patch.object(module, factory, return_value=manager), \
                     patch.object(tuning, "read_ram_kb", return_value=1024 * 1024), \
                     patch.object(backup, "track", side_effect=tracked) as track, \
                     patch("builtins.input", return_value="YES"), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.change(experimental=True, **kwargs), 0)
                track.assert_called_once()
                getattr(manager, method).assert_called_once()

    def test_hy2_primary_operation_is_recorded_before_optional_firewall(self):
        for remove in (False, True):
            with self.subTest(remove=remove):
                manager = Mock()
                calls = []
                def tracked(module, action, operation, **kwargs):
                    calls.append((module, action))
                    return operation()
                def firewall_done(spec, *, with_result=False):
                    self.assertEqual(calls, [("hy2", "apply")])
                    return ("firewall recorded separately", 0) if with_result else "firewall recorded separately"
                with patch.object(hy2.packages, "preflight", return_value=None), \
                     patch.object(Path, "is_dir", return_value=True), \
                     patch.object(hy2, "Hy2Manager", return_value=manager), \
                     patch.object(backup, "track", side_effect=tracked), \
                     patch.object(hy2, "allow_ufw", side_effect=firewall_done) as firewall, \
                     patch("builtins.input", return_value="YES"), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(hy2.change(hy2.HopSpec("eth0", 20000, 20100, 443, ("ip",)),
                                                remove=remove, allow_firewall=True, experimental=True), 0)
                self.assertEqual(calls, [("hy2", "remove" if remove else "apply")])
                self.assertEqual(firewall.call_count, 0 if remove else 1)

    def test_timezone_entry_records_only_after_confirmation(self):
        for confirmation in ("YES", "NO"):
            with self.subTest(confirmation=confirmation):
                def tracked(module, action, operation, **kwargs):
                    self.assertEqual((module, action), ("timezone", "set"))
                    setter.assert_not_called()
                    return operation()
                with patch.object(common.packages, "preflight", return_value=None), \
                     patch.object(common, "timezone_status", return_value={"effective": "UTC", "configured": "UTC"}), \
                     patch.object(common, "validate_timezone"), patch.object(common, "set_timezone") as setter, \
                     patch.object(backup, "track", side_effect=tracked) as track, \
                     patch("builtins.input", side_effect=["Asia/Shanghai", confirmation]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(common.timezone_change(experimental=True), 0)
                self.assertEqual(track.call_count, 1 if confirmation == "YES" else 0)
                self.assertEqual(setter.call_count, track.call_count)

    def test_confirmed_bbr_change_uses_history_before_manager(self):
        manager = Mock()
        manager.available.return_value = ["bbr"]
        def tracked(module, action, operation, **kwargs):
            self.assertEqual((module, action), ("bbr", "apply"))
            manager.apply.assert_not_called()
            return operation()
        with patch.object(bbr.packages, "preflight", return_value=None), \
             patch.object(bbr, "BBRManager", return_value=manager), \
             patch.object(backup, "track", side_effect=tracked) as track, \
             patch("builtins.input", return_value="YES"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bbr.change(experimental=True), 0)
        track.assert_called_once()
        manager.apply.assert_called_once_with(load_module=False)

    def test_backup_failure_stops_bbr_mutation_and_returns_failure(self):
        manager = Mock()
        manager.available.return_value = ["bbr"]
        with patch.object(bbr.packages, "preflight", return_value=None), \
             patch.object(bbr, "BBRManager", return_value=manager), \
             patch.object(backup, "track", side_effect=backup.BackupFailure("backup unavailable")), \
             patch("builtins.input", return_value="YES"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bbr.change(experimental=True), 1)
        manager.apply.assert_not_called()

    def test_cancelled_bbr_change_does_not_create_history(self):
        manager = Mock()
        manager.available.return_value = ["bbr"]
        with patch.object(bbr.packages, "preflight", return_value=None), \
             patch.object(bbr, "BBRManager", return_value=manager), \
             patch.object(backup, "track") as track, patch("builtins.input", return_value="NO"), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bbr.change(experimental=True), 0)
        track.assert_not_called()
        manager.apply.assert_not_called()

    def test_hy2_ufw_rules_get_independent_history_entries(self):
        manager = Mock()
        manager.command.return_value = "/usr/sbin/ufw"
        manager.status.return_value = "active"
        manager.allow.return_value = "allowed"
        calls = []
        def tracked(module, action, operation, **kwargs):
            calls.append((module, action))
            return operation()
        with patch.object(hy2.firewall, "FirewallManager", return_value=manager), patch.object(backup, "track", side_effect=tracked):
            hy2.allow_ufw(hy2.HopSpec("eth0", 20000, 20100, 443, ("ip",)))
        self.assertEqual(calls, [("ufw", "allow"), ("ufw", "allow")])
        self.assertEqual(manager.allow.call_count, 2)


if __name__ == "__main__":
    unittest.main()
