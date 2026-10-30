import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import bbr, cli


class FakeSysctl:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.fail = None

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if Path(args[0]).name == "modprobe":
            target = self.root / "proc/sys/net/ipv4/tcp_available_congestion_control"
            target.write_text("reno cubic bbr\n", encoding="ascii")
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        key, value = args[-1].split("=", 1)
        if self.fail == (key, value):
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="permission denied")
        target = self.root / "proc/sys" / key.replace(".", "/")
        target.write_text(value + "\n", encoding="ascii")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


class BBRTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("etc/sysctl.d", "run/lock", "var/lib", "proc/sys/net/ipv4", "proc/sys/net/core"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "proc/sys/net/ipv4/tcp_congestion_control").write_text("cubic\n", encoding="ascii")
        (self.root / "proc/sys/net/ipv4/tcp_available_congestion_control").write_text("reno cubic bbr\n", encoding="ascii")
        (self.root / "proc/sys/net/core/default_qdisc").write_text("fq_codel\n", encoding="ascii")
        self.runner = FakeSysctl(self.root)
        self.manager = bbr.BBRManager(self.root, self.runner)
        commands = {"sysctl": "/usr/sbin/sysctl", "modprobe": "/usr/sbin/modprobe"}
        self.find = patch.object(bbr.checks, "find_command", side_effect=commands.get)
        self.find.start()
        self.addCleanup(self.find.stop)

    def test_apply_repeat_and_restore_preserves_other_files(self):
        unrelated = self.root / "etc/sysctl.d/50-other.conf"
        unrelated.write_text("vm.swappiness = 10\n", encoding="utf-8")
        self.manager.apply()
        self.assertEqual(self.manager.read_live(), bbr.TARGET)
        self.assertEqual(self.manager.config.read_bytes(), bbr.CONFIG)
        before_repeat = len(self.runner.calls)
        self.manager.apply()
        self.assertEqual(len(self.runner.calls), before_repeat)
        self.manager.restore()
        self.assertEqual(self.manager.read_live(), {bbr.TCP: "cubic", bbr.QDISC: "fq_codel"})
        self.assertFalse(self.manager.config.exists())
        self.assertFalse(self.manager.state.exists())
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "vm.swappiness = 10\n")

    def test_second_write_failure_rolls_back_first(self):
        self.runner.fail = (bbr.QDISC, "fq")
        with self.assertRaises(bbr.BBRFailure):
            self.manager.apply()
        self.assertEqual(self.manager.read_live(), {bbr.TCP: "cubic", bbr.QDISC: "fq_codel"})
        self.assertFalse(self.manager.state.exists())
        self.assertFalse(self.manager.config.exists())

    def test_conflicting_existing_settings_prevent_changes(self):
        (self.root / "etc/sysctl.conf").write_text("net.ipv4.tcp_congestion_control = cubic\n", encoding="utf-8")
        with self.assertRaisesRegex(bbr.BBRFailure, "冲突"):
            self.manager.apply()
        self.assertEqual(self.runner.calls, [])

    def test_existing_config_is_not_overwritten(self):
        self.manager.config.write_text("owner content\n", encoding="utf-8")
        with self.assertRaisesRegex(bbr.BBRFailure, "已存在"):
            self.manager.apply()
        self.assertEqual(self.manager.config.read_text(encoding="utf-8"), "owner content\n")
        self.assertEqual(self.runner.calls, [])

    def test_external_runtime_change_blocks_restore(self):
        self.manager.apply()
        (self.root / "proc/sys/net/ipv4/tcp_congestion_control").write_text("reno\n", encoding="ascii")
        with self.assertRaisesRegex(bbr.BBRFailure, "其他操作"):
            self.manager.restore()
        self.assertEqual(self.manager.read_live()[bbr.TCP], "reno")
        self.assertTrue(self.manager.config.exists())
        self.assertTrue(self.manager.state.exists())

    def test_external_config_change_blocks_restore(self):
        self.manager.apply()
        self.manager.config.write_text("user edit\n", encoding="utf-8")
        with self.assertRaisesRegex(bbr.BBRFailure, "外部修改"):
            self.manager.restore()
        self.assertEqual(self.manager.config.read_text(encoding="utf-8"), "user edit\n")

    def test_missing_bbr_refuses_without_writes(self):
        (self.root / "proc/sys/net/ipv4/tcp_available_congestion_control").write_text("reno cubic\n", encoding="ascii")
        with self.assertRaisesRegex(bbr.BBRFailure, "未列出"):
            self.manager.apply()
        self.assertEqual(self.runner.calls, [])

    def test_bbr_module_is_loaded_only_when_authorized(self):
        (self.root / "proc/sys/net/ipv4/tcp_available_congestion_control").write_text("reno cubic\n", encoding="ascii")
        self.manager.apply(load_module=True)
        self.assertEqual(self.runner.calls[0], ("/usr/sbin/modprobe", "tcp_bbr"))
        self.assertEqual(self.manager.read_live(), bbr.TARGET)

    def test_symlinked_config_is_not_followed(self):
        target = self.root / "external"
        target.write_text("keep\n", encoding="utf-8")
        self.manager.config.symlink_to(target)
        with self.assertRaisesRegex(bbr.BBRFailure, "已存在"):
            self.manager.apply()
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

    def test_demo_cannot_modify(self):
        with patch("builtins.input", side_effect=["1", "2", "0"]), \
             patch.object(bbr, "change", side_effect=AssertionError("must not run")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            cli.bbr_menu(demo=True, experimental=True)
        self.assertIn("不会读取本机、联网或执行修改", out.getvalue())


if __name__ == "__main__":
    unittest.main()
