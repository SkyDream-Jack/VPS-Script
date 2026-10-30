"""执行真实生成命令，但下载器和 PATH 都在临时目录内；不联网、不安装。"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release.prepare_test_version import short_command


class RootEntryTest(unittest.TestCase):
    def test_no_sudo_needed_and_ssh_context_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("bash", "mktemp", "rm"):
                (root / name).symlink_to(shutil.which(name))
            # 下载替身仅写一个打印 SSH 上下文的脚本，绝不访问网络。
            curl = root / "curl"
            curl.write_text("#!/bin/sh\nprintf '%s\\n' 'printf \"%s\\n\" \"$SSH_CONNECTION\"' > \"$4\"\n")
            curl.chmod(0o755)
            context = "192.0.2.1 40000 192.0.2.2 22"
            result = subprocess.run(("/bin/bash", "-c", short_command("https://example.invalid/install.sh")),
                                    env={"PATH": str(root), "TMPDIR": str(root), "SSH_CONNECTION": context},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), context)
            self.assertFalse(any(path.name.startswith("tmp.") for path in root.iterdir()))

    def test_failed_download_never_executes_partial_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("bash", "mktemp", "rm"):
                (root / name).symlink_to(shutil.which(name))
            curl = root / "curl"
            curl.write_text('#!/bin/sh\nprintf \'echo SHOULD_NOT_EXECUTE\\n\' > "$4"\nexit 22\n')
            curl.chmod(0o755)
            result = subprocess.run(("/bin/bash", "-c", short_command("https://example.invalid/install.sh")),
                                    env={"PATH": str(root), "TMPDIR": str(root)},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 22)
            self.assertNotIn("SHOULD_NOT_EXECUTE", result.stdout)


if __name__ == "__main__":
    unittest.main()
