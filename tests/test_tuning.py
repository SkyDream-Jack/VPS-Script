import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import tuning


BASE_VALUES = {
    "net.core.somaxconn": "128",
    "net.core.netdev_max_backlog": "1000",
    "net.ipv4.tcp_max_syn_backlog": "1024",
    "net.ipv4.ip_local_port_range": "32768 60999",
    "net.ipv4.tcp_fin_timeout": "60",
    "net.ipv4.tcp_keepalive_time": "7200",
    "net.ipv4.tcp_keepalive_intvl": "75",
    "net.ipv4.tcp_keepalive_probes": "9",
    "net.ipv4.tcp_mtu_probing": "0",
    "net.ipv4.tcp_sack": "1",
    "net.ipv4.tcp_timestamps": "1",
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_tw_reuse": "0",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.tcp_slow_start_after_idle": "1",
    "net.ipv4.tcp_notsent_lowat": "4294967295",
    "net.ipv4.tcp_fastopen": "1",
    "net.core.rmem_max": "212992",
    "net.core.wmem_max": "212992",
    "net.ipv4.tcp_rmem": "4096 131072 6291456",
    "net.ipv4.tcp_wmem": "4096 16384 4194304",
    "net.ipv4.tcp_mem": "100 200 300",
    "net.ipv4.tcp_adv_win_scale": "1",
    "net.ipv4.tcp_moderate_rcvbuf": "1",
    "net.netfilter.nf_conntrack_max": "65536",
}


class FakeSysctl:
    def __init__(self, values):
        self.values = dict(values)
        self.calls = []
        self.fail_once = None

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[1] == "-n":
            key = args[2]
            if key not in self.values:
                return subprocess.CompletedProcess(args, 1, "", "No such file")
            return subprocess.CompletedProcess(args, 0, self.values[key] + "\n", "")
        if args[1] == "-w":
            key, _, value = args[2].partition("=")
            if self.fail_once == key:
                self.fail_once = None
                return subprocess.CompletedProcess(args, 1, "", "permission denied")
            self.values[key] = value
            return subprocess.CompletedProcess(args, 0, f"{key} = {value}\n", "")
        return subprocess.CompletedProcess(args, 1, "", "unsupported")


class TuningTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("etc/sysctl.d", "run/lock", "var/lib", "proc"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "proc/meminfo").write_text("MemTotal:       1048576 kB\n", encoding="ascii")
        (self.root / "etc/sysctl.conf").write_text("# empty\n", encoding="utf-8")
        self.fake = FakeSysctl(BASE_VALUES)
        self.manager = tuning.TuningManager(self.root, self.fake)
        self.find = patch.object(tuning.checks, "find_command", return_value="/usr/sbin/sysctl")
        self.find.start()
        self.addCleanup(self.find.stop)

    def test_apply_repeat_restore_preserves_other_files(self):
        unrelated = self.root / "etc/sysctl.d/50-other.conf"
        unrelated.write_text("vm.swappiness = 10\n", encoding="utf-8")
        self.manager.apply("conservative")
        self.assertTrue(self.manager.config.exists())
        self.assertTrue(self.manager.state.exists())
        state = json.loads(self.manager.state.read_text(encoding="utf-8"))
        self.assertEqual(state["profile"], "conservative")
        self.assertEqual(self.fake.values["net.core.somaxconn"], "4096")
        writes = sum(1 for args in self.fake.calls if args[1] == "-w")
        self.assertIn("已经一致", self.manager.apply("conservative"))
        self.assertEqual(sum(1 for args in self.fake.calls if args[1] == "-w"), writes)
        self.manager.restore()
        self.assertFalse(self.manager.config.exists())
        self.assertFalse(self.manager.state.exists())
        self.assertEqual(self.fake.values, BASE_VALUES)
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "vm.swappiness = 10\n")

    def test_failed_write_rolls_back(self):
        self.fake.fail_once = "net.ipv4.tcp_fin_timeout"
        with self.assertRaisesRegex(tuning.TuningFailure, "调优未完成"):
            self.manager.apply("conservative")
        self.assertFalse(self.manager.config.exists())
        self.assertFalse(self.manager.state.exists())
        self.assertEqual(self.fake.values, BASE_VALUES)

    def test_changing_profile_or_options_requires_restore(self):
        self.manager.apply("conservative")
        before = dict(self.fake.values)
        for args, kwargs in ((('proxy',), {}), (('conservative',), {'fastopen': True}),
                             (('conservative',), {'rtt_ms': 250})):
            with self.subTest(args=args, kwargs=kwargs):
                with self.assertRaisesRegex(tuning.TuningFailure, "先恢复"):
                    self.manager.apply(*args, **kwargs)
                self.assertEqual(self.fake.values, before)
        self.manager.restore()
        self.manager.apply("proxy", fastopen=True)
        self.assertEqual(self.fake.values["net.ipv4.tcp_fastopen"], "3")
        self.assertEqual(self.fake.values["net.core.somaxconn"], "8192")

    def test_changing_buffer_estimate_requires_restore(self):
        self.manager.apply("buffer", bandwidth_mbps=500, rtt_ms=200)
        for kwargs in ({'bandwidth_mbps': 1000, 'rtt_ms': 200},
                       {'bandwidth_mbps': 500, 'rtt_ms': 100}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(tuning.TuningFailure, "先恢复"):
                    self.manager.apply("buffer", **kwargs)

    def test_partial_apply_and_failed_rollback_can_be_restored_later(self):
        def fail_apply_and_rollback(args, **kwargs):
            if args[1] == "-w" and args[2] in (
                    "net.ipv4.tcp_fin_timeout=15", "net.core.somaxconn=128"):
                return subprocess.CompletedProcess(args, 1, "", "simulated failure")
            return self.fake(args, **kwargs)
        self.manager.runner = fail_apply_and_rollback
        with self.assertRaisesRegex(tuning.TuningFailure, "调优未完成"):
            self.manager.apply("conservative")
        self.assertTrue(self.manager.state.exists())
        self.assertFalse(self.manager.config.exists())
        self.assertEqual(self.fake.values["net.core.somaxconn"], "4096")
        self.manager.runner = self.fake
        self.manager.restore()
        self.assertFalse(self.manager.state.exists())
        self.assertEqual(self.fake.values, BASE_VALUES)

    def test_restore_missing_config_still_rejects_external_live_changes(self):
        self.manager.apply("conservative")
        self.manager.config.unlink()
        self.fake.values["net.core.somaxconn"] = "65535"
        with self.assertRaisesRegex(tuning.TuningFailure, "其他操作"):
            self.manager.restore()
        self.assertTrue(self.manager.state.exists())
        self.assertEqual(self.fake.values["net.core.somaxconn"], "65535")

    def test_rollback_does_not_overwrite_external_live_change(self):
        before = {"net.core.somaxconn": "128"}
        target = {"net.core.somaxconn": "4096"}
        self.fake.values["net.core.somaxconn"] = "65535"
        errors = self.manager._rollback(before, target)
        self.assertTrue(errors)
        self.assertEqual(self.fake.values["net.core.somaxconn"], "65535")

    def test_rollback_timeout_retains_snapshot_for_retry(self):
        def fail_with_timeout(args, **kwargs):
            if args[1] == "-w" and args[2] in (
                    "net.ipv4.tcp_fin_timeout=15", "net.core.somaxconn=128"):
                raise subprocess.TimeoutExpired(args, 10)
            return self.fake(args, **kwargs)
        self.manager.runner = fail_with_timeout
        with self.assertRaisesRegex(tuning.TuningFailure, "调优未完成"):
            self.manager.apply("conservative")
        self.assertTrue(self.manager.state.exists())
        self.manager.runner = self.fake
        self.manager.restore()
        self.assertEqual(self.fake.values, BASE_VALUES)

    def test_failed_restore_can_be_retried_with_remaining_snapshot(self):
        self.manager.apply("conservative")
        self.manager.config.unlink()
        self.fake.fail_once = "net.core.somaxconn"
        with self.assertRaisesRegex(tuning.TuningFailure, "恢复未完全"):
            self.manager.restore()
        self.assertTrue(self.manager.state.exists())
        self.manager.restore()
        self.assertFalse(self.manager.state.exists())
        self.assertEqual(self.fake.values, BASE_VALUES)

    def test_conflict_prevents_changes(self):
        (self.root / "etc/sysctl.d/99-other.conf").write_text(
            "net.core.somaxconn = 1024\n", encoding="utf-8")
        with self.assertRaisesRegex(tuning.TuningFailure, "冲突"):
            self.manager.apply("conservative")
        self.assertFalse(self.manager.config.exists())
        self.assertEqual(self.fake.values, BASE_VALUES)

    def test_external_config_edit_blocks_restore(self):
        self.manager.apply("conservative")
        self.manager.config.write_text("user edit\n", encoding="utf-8")
        with self.assertRaisesRegex(tuning.TuningFailure, "外部修改"):
            self.manager.restore()
        self.assertEqual(self.manager.config.read_text(encoding="utf-8"), "user edit\n")

    def test_proxy_adds_conntrack_and_fastopen(self):
        self.manager.apply("proxy", fastopen=True)
        self.assertEqual(self.fake.values["net.ipv4.tcp_fastopen"], "3")
        self.assertEqual(self.fake.values["net.netfilter.nf_conntrack_max"], "65536")
        self.assertIn("tcp_slow_start_after_idle = 0", self.manager.config.read_text(encoding="utf-8"))
        self.manager.restore()
        self.assertEqual(self.fake.values, BASE_VALUES)

    def test_buffer_values_are_bounded(self):
        values = tuning.buffer_values(1024 * 1024, 500, 200)
        buf_max = int(values["net.core.rmem_max"])
        self.assertGreaterEqual(buf_max, 4 * 1024 * 1024)
        self.assertLessEqual(buf_max, 128 * 1024 * 1024)
        self.assertTrue(values["net.ipv4.tcp_rmem"].endswith(str(buf_max)))
        self.assertEqual(len(values["net.ipv4.tcp_mem"].split()), 3)
        with self.assertRaises(tuning.TuningFailure):
            tuning.buffer_values(1024 * 1024, 0, 200)
        with self.assertRaises(tuning.TuningFailure):
            tuning.buffer_values(1024 * 1024, 500, 0)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(tuning.TuningFailure):
            tuning.target_values("turbo", 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
