"""菜单的 JSON 契约与演示模式边界；所有外部动作都被拦截。"""

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli


class CLIRegressionTest(unittest.TestCase):
    def test_doctor_json_has_no_text_prefix(self):
        payload = {"schema": 1, "section": "all", "sections": []}
        with patch.object(cli.platform, "system", return_value="Linux"), \
             patch.object(cli.status, "collect", return_value=payload), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["doctor", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue()), payload)

    def test_demo_doctor_json_is_structured_without_collecting(self):
        with patch.object(cli.status, "collect", side_effect=AssertionError("must not inspect host")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["doctor", "--json", "--demo"]), 0)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["demo"])
        self.assertEqual(payload["schema"], 1)

    def test_demo_preview_never_downloads_any_external_script(self):
        for key in cli.external.SPECS:
            with self.subTest(key=key), \
                 patch("builtins.input", side_effect=["10", key, "0"]), \
                 patch.object(cli.external, "download", side_effect=AssertionError("must not download")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                cli.test_menu(demo=True)
            self.assertIn("不会下载", output.getvalue())

    def test_real_preview_remains_available(self):
        with patch("builtins.input", side_effect=["10", "nq", "0"]), \
             patch.object(cli.external, "preview") as preview, \
             contextlib.redirect_stdout(io.StringIO()):
            cli.test_menu()
        preview.assert_called_once_with("nq")

    def test_maintenance_uses_documented_root_command(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from release import prepare_test_version
        self.assertEqual(cli.UPDATE_COMMAND, prepare_test_version.short_command(
            prepare_test_version.LATEST_ROOT + "/install.sh"))


if __name__ == "__main__":
    unittest.main()
