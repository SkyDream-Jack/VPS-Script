import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import checks, cli, status


class StatusTest(unittest.TestCase):
    @staticmethod
    def section(name, facts=None, items=None):
        return {"name": name, "title": status.SECTIONS[name], "facts": facts or {}, "items": items or []}

    @staticmethod
    def payload(sections):
        return {"schema": 1, "generated_at": "2026-10-30T12:00:00+00:00",
                "host": "private-host.example", "section": "overview", "sections": sections}

    def test_aliases_and_all_sections(self):
        self.assertEqual(status.names_for("security"), ("ssh", "ufw", "fail2ban"))
        self.assertEqual(status.names_for("network"), ("bbr", "tuning", "hy2"))
        self.assertEqual(status.names_for("common"), ("swap", "timezone", "dns"))
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

    def test_overview_calls_only_its_three_collectors(self):
        collectors = {name: Mock(return_value=self.section(name)) for name in status.SECTIONS}
        with patch.dict(status._COLLECTORS, collectors, clear=True):
            payload = status.collect_overview()
        self.assertEqual([section["name"] for section in payload["sections"]], ["system", "ssh", "ufw"])
        self.assertEqual(payload["section"], "overview")
        self.assertEqual(set(payload), {"schema", "generated_at", "host", "section", "sections"})
        for name, collector in collectors.items():
            self.assertEqual(collector.call_count, 1 if name in ("system", "ssh", "ufw") else 0)

    def test_overview_only_invokes_fixed_readonly_checks(self):
        with patch.object(checks, "run_check", return_value=checks.Result("unknown", "unavailable")) as run_check, \
             patch("subprocess.run", side_effect=AssertionError("unexpected process")), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("unexpected network")), \
             patch.object(status.panel, "read_settings", side_effect=AssertionError("unrelated panel check")):
            payload = status.collect_overview()
        self.assertEqual([section["name"] for section in payload["sections"]], ["system", "ssh", "ufw"])
        self.assertEqual([call.args[0] for call in run_check.call_args_list],
                         ["ssh_service", "sshd_service", "ssh_socket", "sshd_config", "listening", "ufw"])

    def test_selected_collectors_preserve_order_and_isolate_errors(self):
        collectors = {
            "system": Mock(return_value=self.section("system")),
            "ssh": Mock(side_effect=RuntimeError("private detail")),
            "ufw": Mock(return_value=self.section("ufw")),
        }
        with patch.dict(status._COLLECTORS, collectors, clear=True):
            payload = status.collect_selected(("ssh", "system", "ssh", "ufw"), section="menu")
        self.assertEqual([section["name"] for section in payload["sections"]], ["ssh", "system", "ufw"])
        self.assertEqual(payload["section"], "menu")
        self.assertEqual(payload["sections"][0]["items"][0]["state"], "unknown")
        self.assertEqual(collectors["ssh"].call_count, 1)
        summary = status.render_summary(payload)
        self.assertIn("未知项 1", summary)
        self.assertNotIn("private detail", summary)

    def test_selected_invalid_name_is_rejected_before_any_collection(self):
        collector = Mock(return_value=self.section("system"))
        with patch.dict(status._COLLECTORS, {"system": collector}, clear=True):
            with self.assertRaises(KeyError):
                status.collect_selected(("system", "missing"))
            with self.assertRaises(TypeError):
                status.collect_selected("system")
        collector.assert_not_called()

    def test_public_collection_keeps_schema_and_alias_behavior(self):
        collectors = {name: Mock(return_value=self.section(name)) for name in status.SECTIONS}
        with patch.dict(status._COLLECTORS, collectors, clear=True):
            payload = status.collect("network")
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["section"], "network")
        self.assertEqual([section["name"] for section in payload["sections"]], ["bbr", "tuning", "hy2"])
        self.assertEqual(json.loads(status.dumps(payload)), payload)
        self.assertIn("=== BBR / fq ===", status.render(payload))

    def test_summary_shows_useful_facts_and_preserves_unknowns(self):
        payload = self.payload([
            self.section("system", {"系统": "Ubuntu 24.04 LTS", "内存": "总 1024 MiB / 可用 512 MiB", "根分区": "4 / 20 GiB 已用"}),
            self.section("ssh", {"有效端口": "22、2222", "密码认证": "no", "公钥认证": "yes"},
                         [{"state": "warn"}, {"state": "unknown"}, {"state": "unknown"}]),
            self.section("ufw", {"状态": "active", "IPv6": "yes"}),
        ])
        summary = status.render_summary(payload)
        self.assertIn(payload["generated_at"], summary)
        self.assertIn("Ubuntu 24.04 LTS", summary)
        self.assertIn("总 1024 MiB / 可用 512 MiB", summary)
        self.assertIn("4 / 20 GiB 已用", summary)
        self.assertIn("SSH 端口 22、2222；密码 no / 交互 未知 / 公钥 yes", summary)
        self.assertIn("注意项 1 / 未知项 2", summary)
        self.assertIn("UFW active；IPv6 yes", summary)
        self.assertEqual(len(summary.splitlines()), 4)
        missing = status.render_summary(self.payload([self.section("system"), self.section("ssh"), self.section("ufw")]))
        self.assertIn("系统 未知", missing)
        self.assertIn("内存 未知", missing)
        self.assertIn("SSH 端口 未知", missing)
        self.assertIn("UFW 未知", missing)

    def test_summary_is_bounded_does_not_mutate_payload_or_show_sensitive_details(self):
        secret = "PRIVATE_TOKEN_203.0.113.47"
        sections = [self.section(name, {"规则摘要": secret, "监听": secret, "面板路径": secret},
                                 [{"state": "warn", "name": secret, "detail": secret}])
                    for name in status.SECTIONS]
        sections[0]["facts"].update({"系统": "Ubuntu\n\x1b[31m" + "x" * 5000, "内存": "y" * 5000})
        payload = self.payload(sections * 3)
        before = copy.deepcopy(payload)
        with patch.dict(status._COLLECTORS, {name: Mock(side_effect=AssertionError("render collected")) for name in status.SECTIONS}):
            summary = status.render_summary(payload)
        self.assertLessEqual(len(summary), status.SUMMARY_MAX_CHARS)
        self.assertLessEqual(len(summary.splitlines()), 16)
        self.assertNotIn(secret, summary)
        self.assertNotIn(payload["host"], summary)
        self.assertNotIn("\x1b", summary)
        self.assertIn("…", summary)
        self.assertEqual(payload, before)

    def test_section_summaries_use_only_short_allowlisted_facts(self):
        payload = self.payload([
            self.section("packages", {"包管理器": "APT", "需要重启": "未标记", "软件源": "https://private-source"}),
            self.section("panel", {"服务": "active / enabled", "端口": "2053", "面板路径": "/private-path"}),
            self.section("bbr", {"TCP 拥塞控制": "bbr", "默认队列": "fq"}),
            self.section("tuning", {"档位": "保守", "配置内容": "匹配"}),
            self.section("fail2ban", {"服务": "active / enabled", "封禁 IP": "192.0.2.1"}),
            self.section("hy2", {"服务": "active / enabled", "跳跃范围": "20000-30000", "目标端口": "443"}),
            self.section("swap", {"项目 swap": "active", "大小": "1024 MiB"}),
            self.section("timezone", {"有效时区": "Asia/Shanghai"}),
            self.section("dns", {"名称服务器": "192.0.2.1、2001:db8::1", "搜索域": "private.internal"}),
        ])
        summary = status.render_summary(payload)
        for text in ("APT", "2053", "TCP 拥塞控制 bbr", "默认队列 fq", "配置 匹配",
                     "Fail2ban active / enabled", "20000-30000 → 443", "1024 MiB", "Asia/Shanghai", "服务器数量 2"):
            self.assertIn(text, summary)
        for text in ("private-source", "private-path", "192.0.2.1", "2001:db8::1", "private.internal"):
            self.assertNotIn(text, summary)

    def test_summary_rejects_invalid_ports_and_unknown_states(self):
        payload = self.payload([
            self.section("ssh", {"有效端口": "22 203.0.113.4", "密码认证": "unexpected"}),
            self.section("ufw", {"状态": "unexpected", "IPv6": "unexpected"}),
            self.section("hy2", {"跳跃范围": "65536-99999", "目标端口": "secret"}),
        ])
        summary = status.render_summary(payload)
        for text in ("203.0.113.4", "unexpected", "65536", "secret"):
            self.assertNotIn(text, summary)
        self.assertIn("SSH 端口 未知", summary)
        self.assertIn("UFW 未知", summary)
        self.assertIn("范围 未知 → 未知", summary)

    def ssh_auth_status(self, password="no", interactive="no", pubkey="yes", methods="any", root="yes"):
        values = {"port": "22", "passwordauthentication": password,
                  "kbdinteractiveauthentication": interactive, "pubkeyauthentication": pubkey,
                  "authenticationmethods": methods, "permitrootlogin": root}
        output = "\n".join(f"{key} {value}" for key, value in values.items() if value is not None)
        with patch.object(checks, "run_check", side_effect=lambda name:
                          checks.Result("ok", output) if name == "sshd_config" else checks.Result("unknown", "fixture")):
            return status._ssh()

    def test_any_auth_method_does_not_claim_password_is_enabled_or_key_only(self):
        section = self.ssh_auth_status()
        items = {item["name"]: item for item in section["items"]}
        for name in ("仅公钥认证", "root 登录"):
            self.assertEqual(items[name]["state"], "unknown")
            self.assertIn("尚未确认", items[name]["detail"])
            self.assertNotIn("仍启用", items[name]["detail"])
            self.assertNotIn("只能使用密钥", items[name]["detail"])
        self.assertEqual(section["facts"]["认证方法"], "any")
        self.assertEqual(section["facts"]["密码认证"], "no")
        self.assertEqual(section["facts"]["root 登录"], "yes")

    def test_missing_authentication_methods_remains_unknown(self):
        section = self.ssh_auth_status(methods=None)
        items = {item["name"]: item for item in section["items"]}
        self.assertNotIn("认证方法", section["facts"])
        self.assertEqual(items["仅公钥认证"]["state"], "unknown")
        self.assertEqual(items["root 登录"]["state"], "unknown")

    def test_explicit_publickey_with_disabled_password_is_reported_as_configuration(self):
        section = self.ssh_auth_status(methods="publickey")
        items = {item["name"]: item for item in section["items"]}
        self.assertEqual(items["仅公钥认证"]["state"], "ok")
        self.assertIn("publickey", items["仅公钥认证"]["detail"])
        self.assertIn("实际登录仍需验证", items["仅公钥认证"]["detail"])
        self.assertEqual(items["root 登录"]["state"], "info")

    def test_enabled_password_switch_is_not_claimed_to_override_authentication_methods(self):
        for password, interactive, methods in (("yes", "no", "any"), ("no", "yes", "any"),
                                               ("yes", "no", "publickey")):
            with self.subTest(password=password, interactive=interactive, methods=methods):
                section = self.ssh_auth_status(password=password, interactive=interactive, methods=methods)
                items = {item["name"]: item for item in section["items"]}
                for name in ("仅公钥认证", "root 登录"):
                    self.assertEqual(items[name]["state"], "warn")
                    self.assertIn("开关仍开启", items[name]["detail"])
                    self.assertIn("AuthenticationMethods", items[name]["detail"])

    def test_missing_authentication_flags_remain_unknown(self):
        section = self.ssh_auth_status(password=None, interactive=None, pubkey=None, methods=None)
        items = {item["name"]: item for item in section["items"]}
        self.assertEqual(items["仅公钥认证"]["state"], "unknown")
        self.assertEqual(items["root 登录"]["state"], "unknown")
        self.assertIn("字段不完整", items["仅公钥认证"]["detail"])

    def test_disabled_publickey_is_not_reported_as_key_only(self):
        section = self.ssh_auth_status(pubkey="no", methods="publickey")
        item = next(item for item in section["items"] if item["name"] == "仅公钥认证")
        self.assertEqual(item["state"], "warn")
        self.assertIn("公钥认证也未启用", item["detail"])

    def test_prohibit_password_policy_does_not_alone_imply_publickey_only(self):
        for root in ("prohibit-password", "without-password"):
            with self.subTest(root=root):
                section = self.ssh_auth_status(root=root)
                item = next(item for item in section["items"] if item["name"] == "root 登录")
                self.assertIn("密码和键盘交互认证被禁止", item["detail"])
                self.assertIn("需结合 AuthenticationMethods", item["detail"])
                self.assertNotIn("仅允许密钥登录", item["detail"])


if __name__ == "__main__":
    unittest.main()
