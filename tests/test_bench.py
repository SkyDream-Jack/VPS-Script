import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import bench, external


class BenchTest(unittest.TestCase):
    def test_parse_ping(self):
        text = ("4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n"
                "rtt min/avg/max/mdev = 10.100/12.200/15.300/1.000 ms\n")
        result = bench.parse_ping(text)
        self.assertEqual(result["loss"], 0.0)
        self.assertEqual(result["avg"], 12.2)

    def test_parse_speed(self):
        result = bench.parse_speed("12500000 25000000 2.0")
        self.assertAlmostEqual(result["mbps"], 100.0)
        self.assertAlmostEqual(result["mib_per_second"], 12500000 / 1024**2)
        with self.assertRaises(bench.BenchFailure):
            bench.parse_speed("bad")

    def test_bandwidth_size_is_bounded_before_download(self):
        with patch.object(bench, "checks") as checks:
            with self.assertRaises(bench.BenchFailure):
                bench.bandwidth_report(0)
            with self.assertRaises(bench.BenchFailure):
                bench.bandwidth_report(101)
            checks.find_command.assert_not_called()

    def test_machine_report_is_read_only_text(self):
        text = bench.machine_report()
        self.assertIn("=== 机器 / 系统 ===", text)
        self.assertIn("只读信息", text)


class ExternalTest(unittest.TestCase):
    def test_specs_are_fixed_and_documented(self):
        for key in ("nq", "tq", "ipquality", "netquality", "yabs"):
            spec = external.SPECS[key]
            self.assertTrue(spec.url.startswith("https://"))
            self.assertTrue(spec.source.startswith("https://github.com/"))
            self.assertTrue(spec.official)
            self.assertTrue(spec.license)

    def test_unknown_key_is_rejected(self):
        with self.assertRaises(external.ExternalFailure):
            external.download("unknown")

    def test_run_requires_experimental_before_download(self):
        with contextlib.redirect_stdout(io.StringIO()) as output, \
             patch.object(external, "download", side_effect=AssertionError("must not download")):
            self.assertEqual(external.run("nq", experimental=False), 2)
        self.assertIn("修改模式", output.getvalue())

    def test_redirect_to_foreign_host_is_rejected(self):
        with self.assertRaises(external.ExternalFailure):
            external.SafeRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example/x")

    def test_preview_does_not_execute(self):
        spec = external.SPECS["nq"]
        with patch.object(external, "download", return_value=(spec, b"#!/bin/bash\necho hi\n", "a" * 64)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            external.preview("nq")
        text = output.getvalue()
        self.assertIn("本次下载 SHA-256", text)
        self.assertIn("没有执行", text)
        self.assertIn("echo hi", text)


if __name__ == "__main__":
    unittest.main()
