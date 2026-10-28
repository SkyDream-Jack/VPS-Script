"""在临时目录检查安装器依赖的系统工具；不执行实际安装。"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "需要真实 Linux 系统工具")
class LinuxInstallerUtilitiesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def command(self, name, *args):
        executable = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertIsNotNone(executable, f"缺少系统工具: {name}")
        return subprocess.run((executable, *map(str, args)), capture_output=True,
                              text=True, timeout=10, check=False)

    def test_stage_install_and_move_to_new_directory(self):
        result = self.command("mktemp", "-d", self.root / ".vps-script.XXXXXXXX")
        self.assertEqual(result.returncode, 0, result.stderr)
        stage = Path(result.stdout.strip())
        self.assertEqual(stage.parent, self.root)
        source = self.root / "source"
        source.write_bytes(b"example\n")
        target_file = stage / "example"
        result = self.command("install", "-m", "0644", source, target_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command("stat", "-c", "%u %a", "--", target_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), f"{os.geteuid()} 644")
        self.assertEqual(target_file.read_bytes(), b"example\n")
        destination = self.root / "destination"
        result = self.command("mv", "-T", "-n", "--", stage, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(stage.exists())
        self.assertEqual((destination / "example").read_bytes(), b"example\n")

    def test_move_does_not_replace_existing_empty_directory(self):
        stage = self.root / "stage"
        destination = self.root / "destination"
        stage.mkdir()
        (stage / "example").write_bytes(b"example\n")
        destination.mkdir()
        # 不同实现可能用不同退出码表示跳过；不覆盖且保留源目录才是安全要求。
        self.command("mv", "-T", "-n", "--", stage, destination)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertEqual((stage / "example").read_bytes(), b"example\n")


if __name__ == "__main__":
    unittest.main()
