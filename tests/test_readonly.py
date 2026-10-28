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
from vps_admin import checks, cli


class ReadOnlyChecksTest(unittest.TestCase):
    def test_os_release_is_parsed_without_executing_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "should-not-exist"
            release = Path(directory) / "os-release"
            release.write_text(
                'PRETTY_NAME="Example OS"\n'
                'ID=example\nVERSION_ID="12"\n'
                f'PRETTY_NAME="$(touch {marker})"\n', encoding="utf-8"
            )
            result = checks.os_release(str(release))
            self.assertEqual(result["PRETTY_NAME"], f"$(touch {marker})")
            self.assertEqual(result["VERSION_ID"], "12")
            self.assertFalse(marker.exists())

    def test_missing_command_is_unknown(self):
        with patch.object(checks, "find_command", return_value=None):
            self.assertEqual(checks.run_check("ufw").state, "unknown")

    def test_failed_check_is_not_reported_as_inactive(self):
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="permission denied")
        with patch.object(checks, "find_command", return_value="/usr/sbin/ufw"), \
             patch.object(checks.subprocess, "run", return_value=failed):
            result = checks.run_check("ufw")
        self.assertEqual(result.state, "unknown")
        self.assertEqual(result.exit_code, 1)
        self.assertIn("permission denied", result.output)

    def test_timeout_is_unknown(self):
        with patch.object(checks, "find_command", return_value="/usr/bin/ss"), \
             patch.object(checks.subprocess, "run", side_effect=subprocess.TimeoutExpired("ss", 5)):
            self.assertEqual(checks.run_check("listening").state, "unknown")

    def test_ssh_output_is_filtered_and_command_has_fixed_arguments(self):
        completed = subprocess.CompletedProcess(
            [], 0, stdout="port 22\npasswordauthentication no\nauthorizedkeysfile /private/path\n", stderr=""
        )
        with patch.object(checks, "find_command", return_value="/usr/sbin/sshd"), \
             patch.object(checks.subprocess, "run", return_value=completed) as run:
            result = checks.run_check("sshd_config")
        self.assertEqual(result.output, "port 22\npasswordauthentication no")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ("/usr/sbin/sshd", "-T"))
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 5)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["env"]["PATH"], ":".join(checks.COMMAND_DIRS))

    def test_only_defined_commands_are_accepted(self):
        with self.assertRaises(KeyError):
            checks.run_check("sh -c dangerous")

    def test_demo_never_collects_real_system_data(self):
        with patch.object(checks, "system_report", side_effect=AssertionError("read")), \
             patch.object(checks, "run_check", side_effect=AssertionError("run")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(["status", "--demo"])
        self.assertEqual(code, 0)
        self.assertIn("演示数据", output.getvalue())

    def test_non_linux_refuses_real_checks(self):
        with patch.object(cli.platform, "system", return_value="Darwin"), \
             patch.object(cli, "show_report", side_effect=AssertionError("read")), \
             contextlib.redirect_stderr(io.StringIO()) as output:
            code = cli.main(["status"])
        self.assertEqual(code, 2)
        self.assertIn("仅在 Linux", output.getvalue())

    def test_launcher_ignores_untrusted_working_directory_and_path(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            untrusted = Path(directory)
            marker = untrusted / "should-not-run"
            package = untrusted / "vps_admin"
            package.mkdir()
            (package / "__init__.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n", encoding="utf-8"
            )
            for name in ("python3", "dirname"):
                executable = untrusted / name
                executable.write_text(f"#!/bin/sh\necho bad > '{marker}'\n", encoding="utf-8")
                executable.chmod(0o755)
            env = os.environ.copy()
            env.update({"PATH": directory, "PYTHONPATH": directory})
            completed = subprocess.run(
                [str(project / "vps-admin"), "status", "--demo"], cwd=directory,
                capture_output=True, text=True, timeout=10, env=env, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("演示数据", completed.stdout)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
