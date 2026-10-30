import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import swap


HEADER = "Filename\tType\tSize\tUsed\tPriority\n"


class FakeSwap:
    def __init__(self, root):
        self.root = root
        self.swap = root / "swapfile-vps-script"
        self.proc = root / "proc/swaps"
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        name = Path(args[0]).name
        if name == "fallocate":
            self.swap.write_bytes(b"x")
        elif name == "dd":
            self.swap.write_bytes(b"x")
        elif name == "swapon":
            self.proc.write_text(HEADER + f"{args[1]} file 262144 0 -2\n", encoding="ascii")
        elif name == "swapoff":
            self.proc.write_text(HEADER, encoding="ascii")
        return subprocess.CompletedProcess(args, 0, "", "")


class SwapTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("etc", "proc", "run/lock"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "proc/swaps").write_text(HEADER, encoding="ascii")
        (self.root / "etc/fstab").write_text("UUID=root / ext4 defaults 0 1\n", encoding="utf-8")
        self.fake = FakeSwap(self.root)
        self.manager = swap.SwapManager(self.root, self.fake)

    def test_create_and_remove_manage_only_project_file(self):
        result = self.manager.create(256)
        self.assertIn("已创建", result)
        state = self.manager.status()
        self.assertTrue(state["active"])
        self.assertEqual(state["active_bytes"], 256 * 1024 * 1024)
        self.assertTrue(state["fstab_managed"])
        self.assertIn(swap.FSTAB_LINE, (self.root / "etc/fstab").read_text(encoding="utf-8"))
        self.assertTrue(self.manager.swap.exists())

        self.manager.remove()
        state = self.manager.status()
        self.assertFalse(state["active"])
        self.assertFalse(state["fstab_managed"])
        self.assertFalse(self.manager.swap.exists())
        self.assertEqual((self.root / "etc/fstab").read_text(encoding="utf-8"), "UUID=root / ext4 defaults 0 1\n")

    def test_existing_swap_is_not_touched(self):
        (self.root / "proc/swaps").write_text(HEADER + "/dev/sda2 partition 1048576 0 -2\n", encoding="ascii")
        with self.assertRaisesRegex(swap.SwapFailure, "其他 swap"):
            self.manager.create(256)
        self.assertFalse(self.manager.swap.exists())

    def test_invalid_size_and_duplicate_are_rejected(self):
        for value in (0, 255, 8193, "512", True):
            with self.assertRaises(swap.SwapFailure):
                swap.validate_size(value)
        self.manager.swap.write_bytes(b"x")
        with self.assertRaisesRegex(swap.SwapFailure, "已存在"):
            self.manager.create(256)

    def test_missing_final_newline_preserves_existing_mount_on_create_and_remove(self):
        for suffix in ("", " ", "\t"):
            with self.subTest(suffix=suffix):
                original = "UUID=root / ext4 defaults 0 1" + suffix
                self.manager.fstab.write_text(original, encoding="utf-8")
                self.manager.create(256)
                self.assertEqual(self.manager.fstab.read_text(), original + "\n" + swap.FSTAB_LINE)
                self.assertTrue(self.manager.status()["fstab_managed"])
                self.manager.remove()
                self.assertEqual(self.manager.fstab.read_text(), original + "\n")

    def test_embedded_marker_never_makes_an_existing_mount_removable(self):
        original = "UUID=root / ext4 defaults 0 1 " + swap.FSTAB_LINE
        self.manager.fstab.write_text(original, encoding="utf-8")
        self.manager.swap.write_bytes(b"existing")
        self.assertFalse(self.manager.status()["fstab_managed"])
        with self.assertRaisesRegex(swap.SwapFailure, "没有项目标记"):
            self.manager.remove()
        self.assertEqual(self.manager.fstab.read_text(), original)
        self.assertEqual(self.manager.swap.read_bytes(), b"existing")

    def test_removal_preserves_lookalike_and_unrelated_lines_exactly(self):
        original = "# comment with /swapfile-vps-script # Managed by VPS-Script\nUUID=data /data ext4 defaults 0 2"
        self.manager.fstab.write_text(swap.FSTAB_LINE + original, encoding="utf-8")
        self.manager.swap.write_bytes(b"existing")
        self.manager.remove()
        self.assertEqual(self.manager.fstab.read_text(), original)

    def test_existing_unmanaged_fstab_reference_blocks_create(self):
        original = "/swapfile-vps-script none swap defaults 0 0\n"
        self.manager.fstab.write_text(original, encoding="utf-8")
        with self.assertRaisesRegex(swap.SwapFailure, "已引用"):
            self.manager.create(256)
        self.assertFalse(self.fake.calls)
        self.assertEqual(self.manager.fstab.read_text(), original)

    def test_external_fstab_edit_is_not_overwritten(self):
        original = self.manager.fstab.read_text()
        edited = original + "UUID=data /data ext4 defaults 0 2\n"
        make_temp = self.manager._mkstemp
        def concurrent_edit(directory):
            self.manager.fstab.write_text(edited, encoding="utf-8")
            return make_temp(directory)
        with patch.object(self.manager, "_mkstemp", side_effect=concurrent_edit):
            with self.assertRaisesRegex(swap.SwapFailure, "发生变化"):
                self.manager.create(256)
        self.assertEqual(self.manager.fstab.read_text(), edited)
        self.assertFalse(self.manager.swap.exists())


if __name__ == "__main__":
    unittest.main()
