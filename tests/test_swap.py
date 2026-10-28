import subprocess
from pathlib import Path
import sys
import tempfile
import unittest

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
            self.proc.write_text(HEADER + f"{args[1]} 262144 0 -2\n", encoding="ascii")
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
        (self.root / "proc/swaps").write_text(HEADER + "/dev/sda2 1048576 0 -2\n", encoding="ascii")
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


if __name__ == "__main__":
    unittest.main()
