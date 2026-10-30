import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import audit, bounded, cli, security_scan


class BoundedTest(unittest.TestCase):
    def test_output_limit_stops_process_and_preserves_unknown(self):
        result = bounded.run((sys.executable, "-I", "-c", "import sys; sys.stdout.write('x'*1000000)"), limit=1000)
        self.assertFalse(result.complete)
        self.assertLessEqual(len(result.output), 1000)
        self.assertIn("输出限制", result.reason)

    def test_timeout_stops_process(self):
        result = bounded.run((sys.executable, "-I", "-c", "import time; time.sleep(10)"), timeout=0.1)
        self.assertFalse(result.complete)
        self.assertIn("时间限制", result.reason)

    def test_nonzero_and_terminal_controls_are_not_hidden(self):
        result = bounded.run((sys.executable, "-I", "-c", "import sys; print('bad\\x1b[2J'); sys.exit(7)"))
        self.assertTrue(result.complete)
        self.assertEqual(result.code, 7)
        self.assertNotIn("\x1b", result.output)
        self.assertIn("\\u001b", result.output)

    def test_missing_executable_is_unknown(self):
        self.assertFalse(bounded.run(("/nonexistent-vps-test",)).complete)


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nservice:x:100:100::/nonexistent:/usr/sbin/nologin\n")
        (self.root / "etc/group").write_text("sudo:x:27:alice\n")
        self.calls = []

    def runner(self, args, **kwargs):
        self.calls.append(args)
        name = Path(args[0]).name
        output = ""
        if name == "sshd":
            output = "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin prohibit-password\n"
        elif name == "ufw":
            output = "Status: inactive\n"
        elif name == "fail2ban-client":
            output = "Actions: ufw" if "actions" in args else "Status for the jail: vps-script-sshd\nCurrently banned: 0\n"
        elif name == "journalctl":
            output = "Failed password for invalid user hidden-secret\nAccepted publickey for root from 192.0.2.1\n"
        elif name == "ss":
            output = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((sshd,pid=1,fd=3))"
        return bounded.Result(0, output, True)

    def collect(self, runner=None, commands=None):
        with patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 40000 192.0.2.2 2222", "SUDO_USER": "root"}):
            return audit.Audit(self.root, runner or self.runner, commands or (lambda name: "/usr/bin/" + name)).collect()

    def item(self, report, key):
        return next(item for item in report["items"] if item["id"] == key)

    def test_contextual_ssh_and_ufw_fail2ban_mismatch(self):
        report = self.collect()
        self.assertEqual(self.item(report, "ssh")["state"], "pass")
        self.assertEqual(self.item(report, "fail2ban")["state"], "risk")
        command = next(args for args in self.calls if Path(args[0]).name == "sshd")
        self.assertIn("-C", command)
        self.assertIn("user=root,addr=192.0.2.1,laddr=192.0.2.2,lport=2222", command)

    def test_audit_never_mutates_or_leaks_raw_auth_log(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        report = self.collect()
        self.assertNotIn("hidden-secret", json.dumps(report))
        self.assertEqual(before, sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*")))
        for args in self.calls:
            self.assertFalse(set(args) & {"enable", "disable", "restart", "reload", "install", "update", "--remove"})
        self.assertIn("unknown", report["counts"])
        self.assertEqual(self.item(report, "deep")["state"], "unknown")

    def test_missing_tools_and_errors_remain_unknown(self):
        report = self.collect(commands=lambda name: None)
        for key in ("ssh", "ufw", "fail2ban", "logins", "auth-log", "listeners"):
            self.assertEqual(self.item(report, key)["state"], "unknown")

    def test_extra_uid_zero_account_is_risk(self):
        with (self.root / "etc/passwd").open("a") as file:
            file.write("unknown:x:0:0::/home/unknown:/bin/bash\n")
        self.assertEqual(self.item(self.collect(), "accounts")["state"], "risk")

    def test_public_key_fingerprint_without_key_body_or_comment(self):
        directory = self.root / "root/.ssh"
        directory.mkdir(parents=True, mode=0o700)
        target = directory / "authorized_keys"
        target.write_text("ssh-ed25519 dGVzdC1rZXk= secret-comment\n")
        target.chmod(0o600)
        result = json.dumps(self.item(self.collect(), "keys"))
        self.assertIn("SHA256:", result)
        self.assertNotIn("secret-comment", result)
        self.assertNotIn("dGVzdC1rZXk", result)

    def test_key_symlink_and_fifo_are_not_read(self):
        directory = self.root / "root/.ssh"
        directory.mkdir(parents=True)
        target = directory / "authorized_keys"
        target.symlink_to(self.root / "etc/passwd")
        self.assertEqual(self.item(self.collect(), "keys")["state"], "unknown")
        target.unlink()
        os.mkfifo(target)
        self.assertEqual(self.item(self.collect(), "keys")["state"], "unknown")

    def test_log_sample_limit_is_not_claimed_as_full_coverage(self):
        def run(args, **kwargs):
            if Path(args[0]).name == "journalctl":
                return bounded.Result(0, "Failed password\n" * 300, True)
            return self.runner(args, **kwargs)
        self.assertEqual(self.item(self.collect(run), "auth-log")["state"], "unknown")

    def test_demo_audit_json_uses_no_collectors_or_files(self):
        with patch.object(audit, "Audit", side_effect=AssertionError("host inspection")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["audit", "--demo", "--json"]), 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["demo"])
        self.assertEqual(report["kind"], "security-audit")

    def test_demo_scan_does_not_prompt_or_run(self):
        with patch.object(security_scan, "scan", side_effect=AssertionError("scan")), \
                patch("builtins.input", side_effect=AssertionError("prompt")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["scan", "--scope", "web", "--demo"]), 0)

    def test_readonly_repair_menu_blocks_before_prompts(self):
        with patch("builtins.input", side_effect=["1", "0"]), \
                patch.object(cli.ssh, "change", side_effect=AssertionError("mutation")), \
                patch.object(cli, "show_status"), contextlib.redirect_stdout(io.StringIO()) as output:
            cli.security_repair_menu(experimental=False)
        self.assertIn("只读模式", output.getvalue())


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("tmp", "var/tmp", "proc", "run"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "tmp/sample").write_text("inert fixture, never executed")
        (self.root / "proc/meminfo").write_text("MemAvailable:   5000000 kB\n")
        self.calls = []
        self.result = bounded.Result(0, "Scanned files: 1\nInfected files: 0\n", True)

    def runner(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if "--help" in args:
            return bounded.Result(0, "--fail-if-cvd-older-than=days", True)
        manifest = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--file-list="))
        self.assertEqual(Path(manifest).stat().st_mode & 0o777, 0o600)
        self.assertIn(str(self.root / "tmp/sample"), Path(manifest).read_text())
        return self.result

    def scan(self):
        return security_scan.scan(root=self.root, runner=self.runner, commands=lambda name: "/usr/bin/" + name)

    def test_scan_is_bounded_local_and_does_not_delete_files(self):
        report = self.scan()
        self.assertEqual(report["state"], "review")
        self.assertTrue(report["complete"])
        args, kwargs = self.calls[-1]
        self.assertEqual(kwargs["timeout"], 600)
        self.assertTrue((self.root / "tmp/sample").exists())
        self.assertIn("--official-db-only=yes", args)
        self.assertIn("--fail-if-cvd-older-than=7", args)
        self.assertFalse(any(arg.startswith(("--remove", "--move", "--copy")) for arg in args))
        self.assertFalse(any(p.name.startswith("vps-script-scan-") for p in (self.root / "run/vps-script-security").iterdir()))

    def test_low_memory_blocks_before_loading_engine(self):
        (self.root / "proc/meminfo").write_text("MemAvailable: 500000 kB\n")
        report = self.scan()
        self.assertEqual(self.calls, [])
        self.assertEqual(report["state"], "unknown")
        self.assertIn("内存", report["reason"])

    def test_unavailable_or_old_scanner_never_claims_clean(self):
        self.assertEqual(security_scan.scan(root=self.root, commands=lambda name: None)["state"], "unknown")
        result = security_scan.scan(root=self.root, commands=lambda name: "/usr/bin/clamscan",
                                    runner=lambda *args, **kwargs: bounded.Result(0, "old help", True))
        self.assertIn("兼容性", result["reason"])

    def test_skips_symlink_fifo_oversize_and_marks_incomplete(self):
        (self.root / "tmp/link").symlink_to(self.root / "tmp/sample")
        os.mkfifo(self.root / "tmp/fifo")
        with (self.root / "tmp/big").open("wb") as file:
            file.truncate(security_scan.MAX_FILE_BYTES + 1)
        report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["state"], "unknown")
        self.assertEqual(report["selected_files"], 1)
        self.assertEqual(sum(report["skipped"].values()), 3)

    def test_infection_with_errors_keeps_finding_and_incomplete_state(self):
        self.result = bounded.Result(2, "/tmp/sample: Test.Signature FOUND\nERROR: unreadable\nScanned files: 1\n", True)
        report = self.scan()
        self.assertEqual(report["state"], "risk")
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["findings"]), 1)

    def test_timeout_retains_partial_findings(self):
        self.result = bounded.Result(None, "/tmp/sample: Test.Signature FOUND\n", False, "timeout")
        report = self.scan()
        self.assertEqual(report["state"], "risk")
        self.assertFalse(report["complete"])
        self.assertEqual(report["reason"], "timeout")

    def test_stale_database_or_zero_scanned_is_incomplete(self):
        for result in (bounded.Result(2, "WARNING: database too old", True),
                       bounded.Result(0, "Scanned files: 0\n", True)):
            self.result = result
            report = self.scan()
            self.assertEqual(report["state"], "unknown")
            self.assertFalse(report["complete"])

    def test_limits_and_encryption_alerts_are_not_complete_checks(self):
        for name in ("Heuristics.Limits.Exceeded", "Heuristics.Encrypted.Zip"):
            self.result = bounded.Result(1, f"/tmp/sample: {name} FOUND\nScanned files: 1\n", True)
            self.assertFalse(self.scan()["complete"])

    def test_lock_symlink_prevents_scanner_start(self):
        directory = self.root / "run/vps-script-security"
        directory.mkdir(mode=0o700)
        (directory / "vps-script-security-scan.lock").symlink_to(self.root / "tmp/sample")
        report = self.scan()
        self.assertEqual(len(self.calls), 1)  # Help only.
        self.assertEqual(report["state"], "unknown")

    def test_scope_cannot_inject_path_or_command(self):
        for scope in ("/", "../../etc", "temporary; curl x", "--remove"):
            with self.assertRaises(ValueError):
                security_scan.scan(scope, root=self.root, runner=self.runner)
        self.assertEqual(self.calls, [])
