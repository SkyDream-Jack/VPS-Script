import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli, status


class StatusTest(unittest.TestCase):
    def test_aliases_and_all_sections(self):
        self.assertEqual(status.names_for("security"), ("ssh", "ufw", "fail2ban"))
        self.assertEqual(status.names_for("network"), ("bbr", "tuning", "hy2"))
        self.assertEqual(set(status.names_for("all")), set(status.SECTIONS))

    def test_collect_is_json_serializable_and_has_stable_shape(self):
        payload = status.collect("system")
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["section"], "system")
        self.assertEqual(len(payload["sections"]), 1)
        json.dumps(payload, ensure_ascii=False)
        rendered = status.render(payload)
        self.assertIn("=== 系统概览 ===", rendered)
        self.assertIn("状态生成时间", rendered)

    def test_failing_collector_does_not_break_all(self):
        with patch.dict(status._COLLECTORS, {"system": lambda: (_ for _ in ()).throw(RuntimeError("boom"))}):
            payload = status.collect("system")
        self.assertEqual(payload["sections"][0]["items"][0]["state"], "unknown")
        self.assertIn("boom", payload["sections"][0]["items"][0]["detail"])

    def test_json_cli_output(self):
        with patch.object(cli.platform, "system", return_value="Linux"), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["status", "system", "--json"]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["section"], "system")
        self.assertEqual(payload["sections"][0]["name"], "system")

    def test_unknown_section_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["status", "does-not-exist"])


if __name__ == "__main__":
    unittest.main()
