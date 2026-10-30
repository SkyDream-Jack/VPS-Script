import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import ssh, ssh_rollback


class FakeSSH:
    def __init__(self, root):
        self.root = root
        self.target = root / "etc/ssh/sshd_config.d/00-vps-script.conf"
        self.external_ports = set()
        self.ports = {22}
        self.calls = []
        self.timer_ok = True
        self.socket_mode = False
        self.tx_dir = None
        self.multi_factor = False
        self.fail_worker_reload = False

    def config(self):
        ports = set(self.external_ports)
        auth = False
        if self.target.exists():
            managed, auth = ssh.read_managed(self.target.read_bytes())
            ports |= managed
        if not ports:
            ports = {22}
        return ports, auth

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        name = Path(args[0]).name
        if name == "sshd" and "-T" in args:
            ports, auth = self.config()
            methods = "publickey,password" if self.multi_factor and not auth else ("publickey" if auth else "any")
            output = "".join(f"port {p}\n" for p in sorted(ports))
            output += f"passwordauthentication {'no' if auth else 'yes'}\nkbdinteractiveauthentication {'no' if auth else 'yes'}\npubkeyauthentication yes\nauthenticationmethods {methods}\npermitrootlogin prohibit-password\n"
            return subprocess.CompletedProcess(args, 0, output, "")
        if name == "ss":
            output = "".join(f"LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:*\n" for p in sorted(self.ports))
            return subprocess.CompletedProcess(args, 0, output, "")
        if name == "systemctl" and args[1] == "is-active":
            if args[2].endswith(".timer"):
                return subprocess.CompletedProcess(args, 0 if self.timer_ok else 3, "active\n" if self.timer_ok else "inactive\n", "")
            active = args[2] == ("ssh.socket" if self.socket_mode else "ssh.service")
            return subprocess.CompletedProcess(args, 0 if active else 3, "active\n" if active else "inactive\n", "")
        if name == "systemctl" and args[1] in ("reload", "restart"):
            if self.fail_worker_reload and not kwargs.get("capture_output", False):
                return subprocess.CompletedProcess(args, 1, "", "failed")
            self.ports = self.config()[0]
        if name == "systemd-run":
            self.tx_dir = Path(args[-1])
        if name == "python3":
            rc = ssh_rollback.run(args[-1], target_override=self.target, runner=self)
            return subprocess.CompletedProcess(args, rc, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


class SSHTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in ("run/lock", "run/systemd/system", "var/lib", "etc/ssh/sshd_config.d"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/ssh/sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\n", encoding="utf-8")
        self.fake = FakeSSH(self.root)
        self.manager = ssh.SSHManager(self.root, self.fake)
        commands = {"sshd": "/usr/sbin/sshd", "ss": "/usr/bin/ss", "systemctl": "/usr/bin/systemctl", "systemd-run": "/usr/bin/systemd-run"}
        self.find = patch.object(ssh.checks, "find_command", side_effect=commands.get)
        self.find.start()
        self.addCleanup(self.find.stop)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def change(self, **kwargs):
        return self.manager.change(user="root", address="192.0.2.1", current_port=22, **kwargs)

    def test_new_port_keeps_old_and_confirms(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.change(new_port=2222, verify=lambda: True)
        self.assertIn("新 SSH 端口 2222", output.getvalue())
        self.assertIn("ControlPath=none", output.getvalue())
        self.assertEqual(self.fake.ports, {22, 2222})
        self.assertTrue((self.fake.tx_dir / "confirmed").exists())
        self.assertIn("Port 22", self.fake.target.read_text())
        self.assertIn("Port 2222", self.fake.target.read_text())

    def test_unconfirmed_change_restores_old_configuration(self):
        with self.assertRaisesRegex(ssh.SSHFailure, "未确认"):
            self.change(new_port=2222, verify=lambda: False)
        self.assertFalse(self.fake.target.exists())
        self.assertEqual(self.fake.ports, {22})
        self.assertTrue((self.fake.tx_dir / "rolled-back").exists())

    def test_existing_external_port_is_not_duplicated(self):
        base = self.root / "etc/ssh/sshd_config"
        base.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
        self.fake.external_ports = {22}
        self.change(new_port=2222, verify=lambda: True)
        self.assertNotIn("Port 22\n", self.fake.target.read_text())
        self.assertEqual(self.fake.ports, {22, 2222})

    def test_key_only_is_verified_in_effective_configuration(self):
        self.change(key_only=True, verify=lambda: True)
        config = self.fake.target.read_text()
        self.assertIn("PasswordAuthentication no", config)
        self.assertIn("AuthenticationMethods publickey", config)

    def test_close_owned_old_port_from_new_session(self):
        self.change(new_port=2222, verify=lambda: True)
        self.manager.change(user="root", address="192.0.2.1", current_port=2222,
                            remove_port=22, verify=lambda: True)
        self.assertEqual(self.fake.ports, {2222})
        self.assertNotIn("Port 22\n", self.fake.target.read_text())

    def test_cannot_close_current_or_external_port(self):
        with self.assertRaisesRegex(ssh.SSHFailure, "当前 SSH 会话"):
            self.change(remove_port=22, verify=lambda: True)
        base = self.root / "etc/ssh/sshd_config"
        base.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
        self.fake.external_ports = {22}
        self.change(new_port=2222, verify=lambda: True)
        with self.assertRaisesRegex(ssh.SSHFailure, "其他 SSH 配置文件"):
            self.manager.change(user="root", address="192.0.2.1", current_port=2222,
                                remove_port=22, verify=lambda: True)

    def test_multifactor_is_not_overwritten(self):
        self.fake.multi_factor = True
        with self.assertRaisesRegex(ssh.SSHFailure, "多因素"):
            self.change(key_only=True, verify=lambda: True)
        self.assertFalse(self.fake.target.exists())

    def test_match_configuration_is_rejected(self):
        (self.root / "etc/ssh/sshd_config.d/custom.conf").write_text("Match User admin\n PasswordAuthentication yes\n")
        with self.assertRaisesRegex(ssh.SSHFailure, "Match"):
            self.change(new_port=2222, verify=lambda: True)
        self.assertFalse(self.fake.target.exists())

    def test_unsafe_dropin_directory_is_rejected(self):
        self.manager.dropins.chmod(0o777)
        with self.assertRaisesRegex(ssh.SSHFailure, "权限不安全"):
            self.change(new_port=2222, verify=lambda: True)
        self.assertFalse(self.fake.target.exists())

    def test_unmanaged_file_is_not_overwritten(self):
        self.fake.target.write_text("Port 22\n")
        with self.assertRaisesRegex(ssh.SSHFailure, "不属于本项目"):
            self.change(new_port=2222, verify=lambda: True)
        self.assertEqual(self.fake.target.read_text(), "Port 22\n")

    def test_missing_timer_prevents_config_write(self):
        self.fake.timer_ok = False
        with self.assertRaisesRegex(ssh.SSHFailure, "定时器"):
            self.change(new_port=2222, verify=lambda: True)
        self.assertFalse(self.fake.target.exists())

    def test_pending_old_worker_blocks_even_already_configured_port(self):
        self.change(new_port=2222, verify=lambda: True)
        old = self.fake.tx_dir
        (old / "confirmed").unlink()
        before = self.fake.target.read_bytes()
        calls = len(self.fake.calls)
        with self.assertRaisesRegex(ssh.SSHFailure, "未结束"):
            self.change(new_port=2222, verify=lambda: True)
        self.assertEqual(len(self.fake.calls), calls)
        self.assertEqual(self.fake.target.read_bytes(), before)
        self.assertEqual(ssh_rollback.run(old, target_override=self.fake.target, runner=self.fake), 0)
        self.change(new_port=2222, verify=lambda: True)
        self.assertEqual(self.fake.ports, {22, 2222})

    def test_socket_activation_restarts_socket(self):
        self.fake.socket_mode = True
        self.change(new_port=2222, verify=lambda: True)
        self.assertTrue(any(args[1:] == ("restart", "ssh.socket") for args in self.fake.calls))

    def test_started_rollback_cannot_be_confirmed_even_if_reload_failed(self):
        def timeout_with_failed_reload():
            self.fake.fail_worker_reload = True
            self.assertEqual(ssh_rollback.run(self.fake.tx_dir, target_override=self.fake.target, runner=self.fake), 1)
            return True
        with self.assertRaisesRegex(ssh.SSHFailure, "回滚已"):
            self.change(new_port=2222, verify=timeout_with_failed_reload)
        self.assertFalse((self.fake.tx_dir / "confirmed").exists())
        self.assertTrue((self.fake.tx_dir / "rollback-started").exists())


if __name__ == "__main__":
    unittest.main()
