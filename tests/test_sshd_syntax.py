"""只验证本机 OpenSSH 对临时配置的解析；不会启动 SSH 服务或联网。"""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import ssh


class NativeSSHDTest(unittest.TestCase):
    def test_generated_configuration_parses_with_local_sshd(self):
        sshd = shutil.which("sshd")
        keygen = shutil.which("ssh-keygen")
        if not sshd or not keygen:
            self.skipTest("local OpenSSH tools unavailable")
        with tempfile.TemporaryDirectory(prefix="vps-script-sshd-") as directory:
            root = Path(directory)
            key = root / "hostkey"
            generated = subprocess.run((keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(key)),
                                       capture_output=True, text=True, check=False)
            if generated.returncode != 0:
                self.skipTest("temporary key generation unavailable")
            config = root / "sshd_config"
            config.write_bytes((f"HostKey {key}\n".encode() + ssh.render_managed({22, 2222}, True)))
            result = subprocess.run((sshd, "-T", "-f", str(config)), capture_output=True, text=True, check=False)
            if result.returncode != 0 and "Privilege separation directory" in result.stderr:
                self.skipTest("sshd privilege separation directory unavailable")
            self.assertEqual(result.returncode, 0, result.stderr)
            effective, ports = ssh.parse_effective(result.stdout)
            self.assertEqual(ports, {22, 2222})
            for name, value in ssh.AUTH.items():
                self.assertEqual(effective.get(name), [value])


if __name__ == "__main__":
    unittest.main()
