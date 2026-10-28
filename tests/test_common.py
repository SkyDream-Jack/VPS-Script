import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import common


class CommonTest(unittest.TestCase):
    def test_dns_status_parses_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resolv.conf"
            path.write_text(
                "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n"
                "search example.com corp.example\n", encoding="utf-8")
            result = common.dns_status(path)
        self.assertEqual(result["nameservers"], ("1.1.1.1", "8.8.8.8"))
        self.assertEqual(result["search"], ("example.com", "corp.example"))

    def test_timezone_validation_rejects_injection_and_unknown(self):
        with patch.object(common, "list_timezones", return_value=("Asia/Shanghai", "UTC")):
            self.assertEqual(common.validate_timezone("Asia/Shanghai"), "Asia/Shanghai")
            for value in ("../../etc/passwd", "Asia/Shanghai;reboot", "Mars/Olympus", ""):
                with self.assertRaises(common.CommonFailure):
                    common.validate_timezone(value)

    def test_set_timezone_uses_fixed_command(self):
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(common, "list_timezones", return_value=("UTC",)), \
             patch.object(common.checks, "find_command", return_value="/usr/bin/timedatectl"), \
             patch.object(common, "_run", return_value=completed) as run:
            self.assertIn("UTC", common.set_timezone("UTC"))
        run.assert_called_once_with(("/usr/bin/timedatectl", "set-timezone", "UTC"), timeout=20)


if __name__ == "__main__":
    unittest.main()
