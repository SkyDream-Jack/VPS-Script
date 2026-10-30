import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli, packages


class TTYBuffer(io.StringIO):
    def isatty(self):
        return True


@contextlib.contextmanager
def disposable_linux():
    """仅模拟前置检查；本测试从不执行真实 APT 命令。"""
    output = TTYBuffer()
    with contextlib.redirect_stdout(output), \
         patch.object(packages.platform, "system", return_value="Linux"), \
         patch.object(packages.checks, "os_release", return_value={"ID": "debian"}), \
         patch.object(packages.os, "geteuid", return_value=0), \
         patch.object(packages.sys.stdin, "isatty", return_value=True), \
         patch.object(packages.os.path, "isfile", return_value=True), \
         patch.object(packages.os, "access", return_value=True), \
         patch.object(packages, "source_origins", return_value=((), False)):
        yield output


class PackageActionsTest(unittest.TestCase):
    def setUp(self):
        def recorded(module, action, operation, **kwargs):
            try:
                return operation()
            except Exception as exc:
                raise packages.backup.BackupFailure("recorded command failure") from exc
        tracker = patch.object(packages.backup, "track", side_effect=recorded)
        snapshot = patch.object(packages.backup, "confirm_external_snapshot", return_value=True)
        self.addCleanup(tracker.stop)
        self.addCleanup(snapshot.stop)
        tracker.start()
        snapshot.start()

    def test_default_gate_blocks_before_any_command(self):
        with patch.object(packages.subprocess, "run") as run, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = packages.run_action("update")
        self.assertEqual(result, 2)
        self.assertIn("默认关闭", output.getvalue())
        run.assert_not_called()

    def test_non_debian_and_non_root_are_rejected(self):
        with disposable_linux(), patch.object(packages.subprocess, "run") as run:
            with patch.object(packages.checks, "os_release", return_value={"ID": "rocky"}):
                self.assertEqual(packages.run_action("upgrade", experimental=True), 2)
            with patch.object(packages.os, "geteuid", return_value=1000):
                self.assertEqual(packages.run_action("upgrade", experimental=True), 2)
        run.assert_not_called()

    def test_no_tty_is_rejected(self):
        with disposable_linux(), patch.object(packages.sys.stdin, "isatty", return_value=False), \
             patch.object(packages.subprocess, "run") as run:
            self.assertEqual(packages.run_action("update", experimental=True), 2)
        run.assert_not_called()

    def test_failed_simulation_prevents_modification(self):
        failed = subprocess.CompletedProcess([], 7)
        with disposable_linux() as output, \
             patch.object(packages.subprocess, "run", return_value=failed) as run, \
             patch("builtins.input", side_effect=AssertionError("must not prompt")):
            result = packages.run_action("upgrade", experimental=True)
        self.assertEqual(result, 1)
        self.assertEqual(run.call_count, 1)
        self.assertIn("模拟失败", output.getvalue())
        self.assertIn("--simulate", run.call_args.args[0])

    def test_declining_does_not_run_modification(self):
        simulated = subprocess.CompletedProcess([], 0)
        with disposable_linux(), patch.object(packages.subprocess, "run", return_value=simulated) as run, \
             patch("builtins.input", return_value="no"):
            result = packages.run_action("base", experimental=True)
        self.assertEqual(result, 0)
        self.assertEqual(run.call_count, 1)
        self.assertIn("--simulate", run.call_args.args[0])

    def test_confirmed_install_uses_fixed_packages_and_no_remove(self):
        completed = subprocess.CompletedProcess([], 0)
        with disposable_linux(), patch.object(packages.subprocess, "run", return_value=completed) as run, \
             patch("builtins.input", return_value="YES"):
            result = packages.run_action("network", experimental=True)
        self.assertEqual(result, 0)
        self.assertEqual(run.call_count, 2)
        simulation, execution = run.call_args_list
        self.assertIn("--simulate", simulation.args[0])
        command = execution.args[0]
        self.assertNotIn("--simulate", command)
        self.assertIn("--no-remove", command)
        self.assertNotIn("--yes", command)
        self.assertEqual(command[-5:], ("install", "iproute2", "iputils-ping", "dnsutils", "traceroute"))
        self.assertNotIn("shell", execution.kwargs)

    def test_update_result_does_not_claim_all_sources_succeeded(self):
        with disposable_linux() as output, \
             patch.object(packages.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
             patch("builtins.input", return_value="YES"):
            self.assertEqual(packages.run_action("update", experimental=True), 0)
        self.assertIn("部分源出错", output.getvalue())

    def test_partial_failure_is_reported(self):
        with disposable_linux() as output, \
             patch.object(packages.subprocess, "run", return_value=subprocess.CompletedProcess([], 23)), \
             patch("builtins.input", return_value="YES"):
            self.assertEqual(packages.run_action("update", experimental=True), 23)
        self.assertIn("可能已部分执行", output.getvalue())

    def test_sources_redact_credentials_and_ignore_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sources.list").write_text(
                "# deb https://ignored.example/debian stable main\n"
                "deb https://user:secret@repo.example:8443/private?token=abc stable main\n", encoding="utf-8"
            )
            parts = root / "sources.list.d"
            parts.mkdir()
            (parts / "system.sources").write_text("URIs: http://[2001:db8::1]:8080/debian\n", encoding="utf-8")
            origins, unknown = packages.source_origins(root)
        self.assertFalse(unknown)
        self.assertEqual(origins, ("http://[2001:db8::1]:8080", "https://repo.example:8443"))
        self.assertNotIn("secret", str(origins))
        self.assertNotIn("abc", str(origins))

    def test_environment_drops_loader_injection_but_keeps_proxy(self):
        with patch.dict(os.environ, {"LD_PRELOAD": "/tmp/bad", "http_proxy": "http://proxy.example:8000"}, clear=True):
            env = packages.apt_env()
        self.assertNotIn("LD_PRELOAD", env)
        self.assertEqual(env["http_proxy"], "http://proxy.example:8000")
        self.assertEqual(env["PATH"], packages.SAFE_PATH)

    def test_demo_menu_never_executes_actions(self):
        with patch("builtins.input", side_effect=["1", "1", "1", "0", "0", "0"]), \
             patch.object(packages, "run_action", side_effect=AssertionError("must not run")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = cli.menu(demo=True, experimental=True)
        self.assertEqual(result, 0)
        self.assertIn("不会读取本机、联网或执行修改", output.getvalue())


if __name__ == "__main__":
    unittest.main()
