import subprocess
from pathlib import Path
import unittest


class LocalInstallerTest(unittest.TestCase):
    def test_preview_is_local_and_does_not_install(self):
        project = Path(__file__).resolve().parents[1]
        result = subprocess.run(("/bin/bash", str(project / "install-local.sh"), "--preview"),
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/opt/vps-script", result.stdout)
        self.assertIn("不会下载、安装或修改系统", result.stdout)

    def test_invalid_arguments_do_not_install(self):
        project = Path(__file__).resolve().parents[1]
        result = subprocess.run(("/bin/bash", str(project / "install-local.sh"), "--unknown"),
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("用法", result.stderr)

    def test_upgrade_is_refused_without_linux_root_tty(self):
        project = Path(__file__).resolve().parents[1]
        result = subprocess.run(("/bin/bash", str(project / "install-local.sh"), "--upgrade"),
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertTrue("Linux" in result.stderr or "root" in result.stderr)


if __name__ == "__main__":
    unittest.main()
