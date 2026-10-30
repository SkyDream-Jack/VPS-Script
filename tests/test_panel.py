import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli, panel


class PanelInstallerTest(unittest.TestCase):
    def setUp(self):
        tracker = patch.object(panel.backup, "track", side_effect=lambda module, action, operation, **kwargs: operation())
        snapshot = patch.object(panel.backup, "confirm_external_snapshot", return_value=True)
        self.addCleanup(tracker.stop)
        self.addCleanup(snapshot.stop)
        tracker.start()
        snapshot.start()

    def test_default_gate_never_downloads(self):
        with patch.object(panel.packages, "preflight", return_value="默认关闭"), \
             patch.object(panel, "download_installer") as download, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(panel.install(), 2)
        download.assert_not_called()

    def test_existing_installation_blocks_before_download(self):
        with patch.object(panel.packages, "preflight", return_value=None), \
             patch.object(panel.platform, "machine", return_value="x86_64"), \
             patch.object(panel.Path, "is_dir", return_value=True), \
             patch.object(panel, "existing_installation", return_value=("/etc/x-ui",)):
            self.assertIn("拒绝覆盖", panel.check_environment(True))

    def test_wrong_hash_is_rejected(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"unexpected"
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(panel.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                panel.download_installer()

    def test_oversized_script_is_rejected(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"x" * (panel.MAX_SCRIPT_BYTES + 1)
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(panel.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "大小限制"):
                panel.download_installer()

    def test_cross_origin_redirect_is_rejected(self):
        request = urllib.request.Request(panel.INSTALLER_URL)
        handler = panel.SameOriginRedirect()
        for target in ("http://raw.githubusercontent.com/x", "https://other.example/x", "https://raw.githubusercontent.com:444/x"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "", {}, target)

    def test_changed_environment_prevents_running_downloaded_script(self):
        with patch.object(panel, "check_environment", side_effect=[None, "发现现有安装"]), \
             patch.object(panel, "download_installer", return_value=b"not executed"), \
             patch.object(panel.subprocess, "run") as run, \
             patch("builtins.input", side_effect=["YES", "YES"]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(panel.install(experimental=True), 2)
        run.assert_not_called()

    def test_decline_after_download_does_not_execute(self):
        with patch.object(panel, "check_environment", return_value=None), \
             patch.object(panel, "download_installer", return_value=b"not executed"), \
             patch.object(panel.subprocess, "run") as run, \
             patch("builtins.input", side_effect=["YES", "no"]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(panel.install(experimental=True), 0)
        run.assert_not_called()

    def test_environment_changed_during_snapshot_confirmation_or_journal_blocks_script(self):
        with patch.object(panel, "check_environment", side_effect=[None, None, "发现现有安装"]), \
             patch.object(panel, "download_installer", return_value=b"not executed"), \
             patch.object(panel.tempfile, "NamedTemporaryFile") as temporary, \
             patch.object(panel.subprocess, "run") as run, \
             patch("builtins.input", side_effect=["YES", "YES"]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(panel.install(experimental=True), 2)
        temporary.assert_not_called()
        run.assert_not_called()
        self.assertIn("未启动安装程序", output.getvalue())

    def test_installer_is_executed_with_restricted_environment_and_cleaned_up(self):
        original_named_temp = tempfile.NamedTemporaryFile
        with tempfile.TemporaryDirectory() as directory:
            def local_temp(*args, **kwargs):
                kwargs["dir"] = directory
                return original_named_temp(*args, **kwargs)
            with patch.object(panel, "check_environment", return_value=None), \
                 patch.object(panel, "download_installer", return_value=b"sample"), \
                 patch.object(panel.tempfile, "NamedTemporaryFile", side_effect=local_temp), \
                 patch.object(panel.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run, \
                 patch("builtins.input", side_effect=["YES", "YES"]), \
                 patch.dict(os.environ, {"XUI_MAIN_FOLDER": "/unexpected", "BASH_ENV": "/tmp/bad"}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(panel.install(experimental=True), 0)
            args, kwargs = run.call_args
            self.assertEqual(args[0][0], "/bin/bash")
            self.assertEqual(args[0][-1], panel.VERSION)
            self.assertNotIn("XUI_MAIN_FOLDER", kwargs["env"])
            self.assertNotIn("BASH_ENV", kwargs["env"])
            self.assertEqual(kwargs["env"]["XUI_ENABLE_FAIL2BAN"], "false")
            self.assertFalse(Path(args[0][1]).exists())

    def test_demo_does_not_install(self):
        with patch("builtins.input", side_effect=["1", "0"]), \
             patch.object(panel, "install", side_effect=AssertionError("must not run")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            cli.panel_menu(demo=True, experimental=True)
        self.assertIn("不会读取本机、联网或执行修改", out.getvalue())


if __name__ == "__main__":
    unittest.main()
