"""Initialization flow with real temporary journals; never mutate the host.

Backends and collectors are mocked except backup's bounded storage engine.
These tests do not establish SSH connectivity or firewall/service behavior.
"""

import contextlib
from contextvars import Context
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import backup, cli, packages, wizard


class Adapter:
    def __init__(self):
        self.value = 0

    def capture(self):
        return {"value": self.value, "sensitive": "not-for-terminal-fixture"}

    def restore(self, before, after):
        if self.capture() != after:
            raise backup.BackupFailure("state drift")
        self.value = before["value"]


class WizardFixture(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="vps-wizard-test-"))
        self.store = backup.Store(Path(directory))
        self.adapter = Adapter()
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.inspect = Mock()
        self.recover = Mock()
        self.preflight = self.stack.enter_context(patch.object(packages, "preflight", return_value=None))
        self.first = Mock(side_effect=self.apply)
        self.second = Mock(side_effect=self.apply)
        self.steps = (
            wizard.Step("a", "First", "bbr", self.first, ("bbr", "apply"), "First note"),
            wizard.Step("b", "Second", "bbr", self.second, ("bbr", "apply"), "Second note"),
        )

    def record(self, operation, module="bbr", action="apply"):
        return backup.track(module, action, operation, store=self.store, adapter=self.adapter)

    def apply(self):
        def operation():
            self.adapter.value += 1
        self.record(operation)
        return 0

    def invoke(self, answers, **options):
        options.setdefault("experimental", True)
        with patch("builtins.input", side_effect=answers):
            return wizard.run(self.steps, inspect=self.inspect, recover=self.recover, **options)

    def text(self):
        return self.output.getvalue()


class WizardFlowTest(WizardFixture):
    def test_selection_validates_all_tokens_and_preserves_catalog_order(self):
        self.assertEqual(wizard.select_steps("2,1 2", self.steps), self.steps)
        self.assertEqual(wizard.select_steps("2，1", self.steps), self.steps)
        for value in ("", " ", "all", "1-2", "0", "3", "1 3", "1; reboot", "01", "１"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wizard.select_steps(value, self.steps)

    def test_empty_selection_does_not_select_or_execute_anything(self):
        self.assertEqual(self.invoke(["", "q"]), 0)
        self.first.assert_not_called()
        self.preflight.assert_not_called()
        self.assertFalse(self.store.directory.exists())

    def test_readonly_plans_checks_skips_but_never_prompts_backend(self):
        self.assertEqual(self.invoke(["1 2", "e", "r", "d", "h", "s", "q"], experimental=False), 0)
        self.first.assert_not_called()
        self.second.assert_not_called()
        self.preflight.assert_not_called()
        self.recover.assert_called_once_with(demo=False, experimental=False)
        self.assertFalse(self.store.directory.exists())
        self.assertIn("只读规划不能修改", self.text())
        self.assertIn("First：已跳过", self.text())

    def test_demo_never_runs_preflight_backend_or_backup(self):
        with patch.object(backup, "observe_records", side_effect=AssertionError("demo journal")):
            self.assertEqual(self.invoke(["1 2", "e", "n", "e", "q"], demo=True), 0)
        self.first.assert_not_called()
        self.second.assert_not_called()
        self.preflight.assert_not_called()
        self.assertTrue(all(c.kwargs["demo"] for c in self.inspect.call_args_list))
        self.assertFalse(self.store.directory.exists())

    def test_success_waits_for_next_choice_and_exit_keeps_completed_change(self):
        self.assertEqual(self.invoke(["2 1", "e", "q"]), 0)
        self.first.assert_called_once_with()
        self.second.assert_not_called()
        self.assertEqual(self.adapter.value, 1)
        record = self.store.list()[0]
        self.assertEqual(record["state"], "completed")
        self.assertIn(record["id"], self.text())
        self.assertIn("Second：未执行", self.text())
        self.assertIn("实际效果仍需验证", self.text())
        self.assertNotIn("not-for-terminal-fixture", self.text())

    def test_zero_without_record_is_cancellation_not_success(self):
        self.first.side_effect = lambda: 0
        self.assertEqual(self.invoke(["1", "e", "n"]), 0)
        self.assertIn("已取消或未执行", self.text())
        self.assertNotIn("命令完成", self.text())
        self.assertFalse(self.store.directory.exists())

    def test_no_change_is_not_presented_as_a_new_change(self):
        self.first.side_effect = lambda: self.record(lambda: 0)
        self.assertEqual(self.invoke(["1", "e", "n"]), 0)
        self.assertEqual(self.store.list()[0]["state"], "no_change")
        self.assertIn("未发现受管理状态变化", self.text())

    def test_exit_then_reenter_checks_fresh_state_without_resuming(self):
        self.invoke(["1 2", "e", "q"])
        self.inspect.reset_mock()
        self.assertEqual(self.invoke(["2", "s"]), 0)
        self.assertEqual(self.inspect.call_args_list, [
            call(("system", "ssh", "ufw", "fail2ban"), demo=False, summary=True),
            call("bbr", demo=False, summary=True),
        ])
        self.first.assert_called_once_with()
        self.second.assert_not_called()
        self.assertEqual(len(self.store.list()), 1)

    def test_status_is_rechecked_immediately_before_and_after_execution(self):
        self.first.side_effect = lambda: (self.inspect("operation marker"), self.apply())[1]
        self.invoke(["1", "e", "q"])
        calls = self.inspect.call_args_list
        marker = calls.index(call("operation marker"))
        self.assertEqual(calls[marker - 1], call("bbr", demo=False, summary=True))
        self.assertEqual(calls[marker + 1], call("bbr", demo=False, summary=True))

    def test_preflight_blocks_before_parameter_or_backend_call(self):
        self.preflight.return_value = "requires root tty"
        self.assertEqual(self.invoke(["1", "e", "q"]), 1)
        self.first.assert_not_called()
        self.assertFalse(self.store.directory.exists())
        self.assertIn("前置检查未通过", self.text())

    def test_failed_immediate_status_read_blocks_execution(self):
        self.inspect.side_effect = [None, None, OSError("read failed")]
        self.assertEqual(self.invoke(["1", "e", "q"]), 1)
        self.first.assert_not_called()

    def test_failed_post_status_requires_acknowledgement_to_continue(self):
        self.inspect.side_effect = [None, None, None, OSError("read failed")]
        self.assertEqual(self.invoke(["1 2", "e", "n", "no", "q"]), 1)
        self.second.assert_not_called()
        self.assertIn("操作后状态读取失败", self.text())

    def test_unrecorded_backend_error_never_continues_automatically(self):
        self.first.side_effect = OSError("failure before recording")
        self.assertEqual(self.invoke(["1 2", "e", "q"]), 1)
        self.second.assert_not_called()
        self.assertIn("未完成", self.text())

    def test_failure_persists_journal_and_requires_explicit_continue(self):
        self.first.side_effect = lambda: self.record(lambda: 7)
        self.assertEqual(self.invoke(["1 2", "e", "s", "no", "n", "CONTINUE", "e", "n"]), 1)
        self.first.assert_called_once_with()
        self.second.assert_called_once_with()
        self.assertEqual({r["state"] for r in self.store.list()}, {"failed", "completed"})

    def test_swallowed_failure_cannot_become_success_from_zero_exit(self):
        def swallowed():
            try:
                self.record(lambda: 9)
            except backup.BackupFailure:
                return 0
        self.first.side_effect = swallowed
        self.assertEqual(self.invoke(["1", "e", "q"]), 1)
        self.assertIn("记录待核实", self.text())

    def test_ancillary_success_without_primary_is_partial_not_complete(self):
        def ancillary():
            self.record(lambda: setattr(self.adapter, "value", 1), module="ufw", action="allow")
            return 0
        self.first.side_effect = ancillary
        self.assertEqual(self.invoke(["1", "e", "q"]), 1)
        self.assertIn("仅有附属操作记录", self.text())

    def test_backup_write_failure_blocks_mutation(self):
        with patch.object(self.store, "_write", side_effect=backup.BackupFailure("disk full")):
            self.assertEqual(self.invoke(["1", "e", "q"]), 1)
        self.assertEqual(self.adapter.value, 0)

    def test_unreadable_record_is_not_success_and_no_snapshot_is_printed(self):
        with patch.object(backup, "history", side_effect=backup.BackupFailure("unreadable")):
            self.assertEqual(self.invoke(["1", "e", "q"]), 1)
        self.assertIn("无法核实", self.text())
        self.assertNotIn("not-for-terminal-fixture", self.text())

    def test_reexecution_requires_retry_even_after_success(self):
        self.assertEqual(self.invoke(["1", "e", "e", "no", "e", "RETRY", "n"]), 0)
        self.assertEqual(self.first.call_count, 2)
        self.assertEqual(len(self.store.list()), 2)

    def test_invalid_navigation_does_not_execute_or_skip(self):
        self.assertEqual(self.invoke(["1", "", "n", "all", "q"]), 0)
        self.first.assert_not_called()
        self.assertIn("First：未执行", self.text())

    def test_eof_at_selection_and_step_exits_without_changes(self):
        for answers in ([EOFError()], ["1 2", EOFError()]):
            with self.subTest(answers=answers):
                self.assertEqual(self.invoke(answers), 0)
        self.first.assert_not_called()
        self.assertFalse(self.store.directory.exists())

    def test_keyboard_interrupt_before_selection_exits_cleanly(self):
        self.assertEqual(self.invoke([KeyboardInterrupt()]), 130)
        self.first.assert_not_called()

    def test_interrupt_during_mutation_preserves_record_and_stops_plan(self):
        def interrupted():
            self.adapter.value = 1
            raise KeyboardInterrupt()
        self.first.side_effect = lambda: self.record(interrupted)
        self.assertEqual(self.invoke(["1 2", "e"]), 130)
        self.second.assert_not_called()
        self.assertEqual(self.store.list()[0]["state"], "interrupted")
        self.assertEqual(self.adapter.value, 1)
        self.assertIn("已中断", self.text())

    def test_eof_in_parameter_prompt_stops_plan(self):
        self.first.side_effect = EOFError()
        self.assertEqual(self.invoke(["1 2", "e"]), 130)
        self.second.assert_not_called()

    def test_recovery_reuses_callback_and_refreshes_without_running_next_step(self):
        def restore(**kwargs):
            record = self.store.list()[0]
            backup.restore_record(record["id"], store=self.store, adapter=self.adapter)
        self.recover.side_effect = restore
        self.assertEqual(self.invoke(["1 2", "e", "h", "q"]), 0)
        self.recover.assert_called_once_with(demo=False, experimental=True)
        self.second.assert_not_called()
        self.assertEqual(self.adapter.value, 0)
        self.assertEqual({r["state"] for r in self.store.list()}, {"restored", "completed"})
        self.assertIn("已有完成的恢复记录", self.text())

    def test_observation_does_not_associate_unrelated_context_records(self):
        def multiple_contexts():
            Context().run(self.apply)
            return self.apply()
        self.first.side_effect = multiple_contexts
        self.invoke(["1", "e", "q"])
        rows = self.store.list()
        self.assertEqual(len(rows), 2)
        summary = self.text().split("本次向导结果")[-1]
        self.assertEqual(sum(row["id"] in summary for row in rows), 1)


class ObservationTest(WizardFixture):
    # Keep separate observation assertions while using the same isolated Store.
    def test_nested_observation_collects_only_prepared_records_and_resets(self):
        with backup.observe_records() as outer:
            self.apply()
            with backup.observe_records() as inner:
                self.apply()
            self.apply()
        self.apply()
        self.assertEqual(len(outer), 3)
        self.assertEqual(len(inner), 1)
        self.assertEqual(outer[1], inner[0])
        self.assertEqual(len(self.store.list()), 4)

    def test_running_write_failure_retains_reference_to_prepared_journal(self):
        write = self.store._write
        def fail_running(record, **kwargs):
            if record["state"] == "running":
                raise OSError("disk full")
            return write(record, **kwargs)
        with backup.observe_records() as refs, patch.object(self.store, "_write", side_effect=fail_running):
            with self.assertRaises(backup.BackupFailure):
                self.apply()
        self.assertEqual(len(refs), 1)
        self.assertEqual(wizard.read_records(refs)[0]["state"], "prepared")
        self.assertEqual(self.adapter.value, 0)

    def test_completion_write_failure_preserves_running_record_without_retry(self):
        write = self.store._write
        def fail_completed(record, **kwargs):
            if record["state"] == "completed":
                raise OSError("disk full after operation")
            return write(record, **kwargs)
        with patch.object(self.store, "_write", side_effect=fail_completed):
            self.assertEqual(self.invoke(["1 2", "e", "q"]), 1)
        self.first.assert_called_once_with()
        self.second.assert_not_called()
        self.assertEqual(self.adapter.value, 1)
        row = self.store.list()[0]
        self.assertEqual(row["state"], "running")
        self.assertIn(row["id"], self.text())
        self.assertIn("不要重复执行", self.text())


class WizardPackageIntegrationTest(WizardFixture):
    def test_separate_security_installs_use_existing_snapshot_gate_and_audit_journal(self):
        real_track = backup.track
        def track(*args, **kwargs):
            return real_track(*args, **kwargs, store=self.store)
        for name in ("ufw", "fail2ban"):
            with self.subTest(action=name), patch.object(packages, "source_origins", return_value=((), False)), \
                    patch.object(packages.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as process, \
                    patch.object(backup, "track", side_effect=track), \
                    patch("builtins.input", side_effect=["YES", "SNAPSHOT"]), \
                    backup.observe_records() as refs:
                self.assertEqual(packages.run_action(name, experimental=True), 0)
            record = wizard.read_records(refs)[0]
            self.assertEqual((record["module"], record["action"], record["state"]), ("packages", name, "completed"))
            self.assertFalse(record["restore_supported"])
            self.assertEqual(record["details"]["external_snapshot"], "user_declared_unverified")
            self.assertEqual(process.call_count, 2)  # simulation then actual call, both mocked

    def test_cancel_snapshot_stops_before_real_install_and_creates_no_record(self):
        with patch.object(packages, "source_origins", return_value=((), False)), \
                patch.object(packages.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as process, \
                patch("builtins.input", side_effect=["YES", "no"]), backup.observe_records() as refs:
            self.assertEqual(packages.run_action("ufw", experimental=True), 0)
        process.assert_called_once()
        self.assertIn("--simulate", process.call_args.args[0])
        self.assertEqual(refs, [])


class WizardCLITest(unittest.TestCase):
    def test_init_cli_and_home_forward_modes_without_changing_six_numbered_routes(self):
        with patch.object(cli, "initialization_menu", return_value=0) as run, \
                patch.object(cli.platform, "system", return_value="Linux"), \
                patch.object(cli.status, "collect_overview"), patch.object(cli.status, "render_summary", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["init", "--experimental"]), 0)
            run.assert_called_with(demo=False, experimental=True)
            with patch("builtins.input", side_effect=["i", "0"]):
                self.assertEqual(cli.menu(), 0)
            run.assert_called_with(demo=False, experimental=False)

    def test_init_rejects_status_sections_and_json(self):
        for args in (["init", "ssh"], ["init", "--json"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exited:
                cli.main(args)
            self.assertEqual(exited.exception.code, 2)

    def test_real_demo_walkthrough_never_reads_host_or_journal(self):
        with patch.object(cli.status, "collect", side_effect=AssertionError("host")), \
                patch.object(cli.status, "collect_selected", side_effect=AssertionError("host")), \
                patch.object(backup, "history", side_effect=AssertionError("journal")), \
                patch.object(packages, "preflight", side_effect=AssertionError("preflight")), \
                patch.object(packages, "run_action", side_effect=AssertionError("mutation")), \
                patch("builtins.input", side_effect=["1 9", "e", "n", "h", "1", "3", "0", "e", "q"]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["init", "--demo", "--experimental"]), 0)

    def test_catalog_routes_to_existing_guarded_entrypoints(self):
        cases = (
            *((name, [], cli.packages, "run_action", (name,), {"experimental": True})
              for name in ("update", "upgrade", "base", "ufw", "fail2ban")),
            ("swap", [], cli.swap, "change", (), {"experimental": True}),
            ("timezone", [], cli.common, "timezone_change", (), {"experimental": True}),
            ("ufw-allow", ["443", "", "tcp"], cli.firewall, "allow", (443, 443, "tcp"), {"experimental": True}),
            ("ufw-enable", [], cli.firewall, "enable", (), {"experimental": True}),
            ("ssh-port", ["2222", "yes"], cli.ssh, "change", (), {"new_port": 2222, "open_firewall": True, "experimental": True}),
            ("ssh-key", [], cli.ssh, "change", (), {"key_only": True, "experimental": True}),
            ("fail2ban-config", [], cli.fail2ban, "configure", (), {"experimental": True}),
            ("bbr", [], cli.bbr, "change", (), {"experimental": True}),
            ("panel", [], cli.panel, "install", (), {"experimental": True}),
            ("hy2", ["eth0", "20000", "20100", "443", "46", "yes"], cli.hy2, "change",
             (cli.hy2.HopSpec("eth0", 20000, 20100, 443, ("ip", "ip6")),), {"allow_firewall": True, "experimental": True}),
        )
        for key, answers, module, name, args, kwargs in cases:
            with self.subTest(step=key), patch.object(module, name, return_value=7) as backend, \
                    patch.object(cli, "show_status", side_effect=AssertionError("wizard owns refresh")), \
                    patch.object(packages, "preflight", return_value=None), \
                    patch("builtins.input", side_effect=answers):
                step = next(s for s in cli.initialization_steps(True) if s.key == key)
                self.assertEqual(step.run(), 7)
                backend.assert_called_once_with(*args, **kwargs)

    def test_firewall_install_enable_and_fail2ban_are_separate_in_safe_order(self):
        keys = [step.key for step in cli.initialization_steps(True)]
        self.assertLess(keys.index("ufw"), keys.index("ufw-allow"))
        self.assertLess(keys.index("ufw-allow"), keys.index("ufw-enable"))
        self.assertLess(keys.index("ufw-enable"), keys.index("fail2ban"))
        self.assertLess(keys.index("ssh-port"), keys.index("fail2ban-config"))
        self.assertLess(keys.index("fail2ban"), keys.index("fail2ban-config"))
        self.assertNotIn("fail2ban", packages.ACTIONS["ufw"].arguments)
        self.assertNotIn("ufw", packages.ACTIONS["fail2ban"].arguments)
        self.assertEqual(packages.ACTIONS["security"].arguments,
                         ("install", "ufw", "fail2ban", "python3-systemd"))


if __name__ == "__main__":
    unittest.main()
