import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import checks, cli, status


class StatusTest(unittest.TestCase):
    def test_aliases_and_all_sections(self):
        self.assertEqual(status.names_for("security"), ("ssh", "ufw", "fail2ban"))
        self.assertEqual(status.names_for("network"), ("bbr", "tuning", "hy2"))
        self.assertEqual(set(status.names_for("all")), set(status.SECTIONS))

    def test_collect_is_json_serializable_and_has_stable_shape(self):
        payload = status.collect("system")
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["section"], "system")
        self.assertEqual(len(payload["sections"]), 1)
        json.dumps(payload, ensure_ascii=False)
        rendered = status.render(payload)
        self.assertIn("=== 系统概览 ===", rendered)
        self.assertIn("状态生成时间", rendered)

    def test_failing_collector_does_not_break_all(self):
        with patch.dict(status._COLLECTORS, {"system": lambda: (_ for _ in ()).throw(RuntimeError("boom"))}):
            payload = status.collect("system")
        self.assertEqual(payload["sections"][0]["items"][0]["state"], "unknown")
        self.assertIn("boom", payload["sections"][0]["items"][0]["detail"])

    def test_json_cli_output(self):
        with patch.object(cli.platform, "system", return_value="Linux"), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["status", "system", "--json"]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["section"], "system")
        self.assertEqual(payload["sections"][0]["name"], "system")

    def test_unknown_section_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["status", "does-not-exist"])

    def test_ssh_status_does_not_treat_deny_as_allow(self):
        outputs = {
            "sshd_config": checks.Result("ok", "port 22\n"),
            "ufw": checks.Result("ok", "Status: active\n22/tcp DENY IN Anywhere\n"),
        }
        with patch.object(checks, "run_check", side_effect=lambda key: outputs.get(key, checks.Result("unknown"))):
            result = status._ssh()
        item = next(item for item in result["items"] if item["name"] == "UFW 放行")
        self.assertEqual(item["state"], "warn")
        self.assertIn("拒绝", item["detail"])

    def test_only_explicit_inbound_allow_rules_for_both_families_are_ok(self):
        text = "Status: active\n22/tcp ALLOW IN Anywhere\n22/tcp (v6) ALLOW IN Anywhere (v6)\n"
        item = status._ssh_ufw_item(text, ["22"])
        self.assertEqual(item["state"], "ok")
        self.assertIn("IPv4", item["detail"])
        self.assertIn("IPv6", item["detail"])
        self.assertIn("不证明", item["detail"])

    def test_conditional_or_ambiguous_rules_never_claim_ssh_access(self):
        cases = {
            "outbound": "22/tcp ALLOW OUT Anywhere",
            "source_restricted": "22/tcp ALLOW IN 192.0.2.4",
            "ipv4_only": "22/tcp ALLOW IN Anywhere",
            "ipv6_only": "22/tcp (v6) ALLOW IN Anywhere (v6)",
            "ipv6_restricted": "22/tcp (v6) ALLOW IN 2001:db8::1",
            "earlier_deny": "22/tcp DENY IN 192.0.2.4\n22/tcp ALLOW IN Anywhere\n22/tcp (v6) ALLOW IN Anywhere (v6)",
            "broad_deny": "Anywhere DENY IN 192.0.2.4\n22/tcp ALLOW IN Anywhere\n22/tcp (v6) ALLOW IN Anywhere (v6)",
            "range": "20:25/tcp ALLOW IN Anywhere",
            "destination": "192.0.2.1 22/tcp ALLOW IN Anywhere",
            "interface": "22/tcp on eth0 ALLOW IN Anywhere",
            "unknown_format": "22/tcp ALLOW Anywhere",
            "limit": "22/tcp LIMIT IN Anywhere",
            "reject": "22/tcp REJECT IN Anywhere",
        }
        for name, rules in cases.items():
            with self.subTest(name=name):
                item = status._ssh_ufw_item("Status: active\n" + rules, ["22"])
                self.assertNotEqual(item["state"], "ok")

    def test_every_ssh_port_needs_rule_evidence(self):
        text = "22/tcp ALLOW IN Anywhere\n22/tcp (v6) ALLOW IN Anywhere (v6)\n"
        self.assertNotEqual(status._ssh_ufw_item(text, ["22", "2222"])["state"], "ok")

    def test_fail2ban_tree_output_preserves_counts_without_addresses(self):
        output = (
            "Status for the jail: sshd\n"
            "|- Filter\n"
            "|  |- Currently failed: 2\n"
            "|  |- Total failed: 10\n"
            "|  `- Journal matches: _SYSTEMD_UNIT=ssh.service\n"
            "`- Actions\n"
            "   |- Currently banned: 1\n"
            "   |- Total banned: 3\n"
            "   `- Banned IP list: 192.0.2.1\n"
        )
        self.assertEqual(status._parse_jail(output), {
            "Currently failed": 2, "Total failed": 10,
            "Currently banned": 1, "Total banned": 3,
        })

    def test_fail2ban_plain_counts_and_unknown_lines(self):
        self.assertEqual(status._parse_jail("Currently banned: 0\nTotal banned: 7\n"),
                         {"Currently banned": 0, "Total banned": 7})
        self.assertEqual(status._parse_jail("Banned IP list: 192.0.2.1\nCurrently banned: unknown"), {})


if __name__ == "__main__":
    unittest.main()
