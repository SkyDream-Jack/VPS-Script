"""Menu routes must preserve CLI features without bypassing read-only/demo gates."""

import contextlib
import io
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vps_admin import cli


def payload(name="overview"):
    return {"schema": 1, "section": name, "sections": []}


class MenuNavigationTest(unittest.TestCase):
    TOP_LEVEL = ("system_menu", "security_menu", "proxy_menu", "network_menu", "test_menu", "maintenance_menu")

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.collect = self.stack.enter_context(patch.object(cli.status, "collect", side_effect=lambda name: payload(name)))
        self.overview = self.stack.enter_context(patch.object(cli.status, "collect_overview", return_value=payload(), create=True))
        self.stack.enter_context(patch.object(cli.status, "render_summary", return_value="cached overview", create=True))
        self.stack.enter_context(patch.object(cli.status, "render", return_value="status details"))

    def stub_main_routes(self):
        return {name: self.stack.enter_context(patch.object(cli, name)) for name in self.TOP_LEVEL}

    def run_menu(self, answers, **options):
        with patch("builtins.input", side_effect=answers):
            return cli.menu(**options)

    def test_home_has_six_numbered_groups(self):
        self.assertEqual(self.run_menu(["0"]), 0)
        text = self.output.getvalue()
        numbered = set(re.findall(r"(?m)^\s*(\d+)\.", text))
        self.assertEqual(numbered, {"0", "1", "2", "3", "4", "5", "6"})
        for label in ("系统与软件", "SSH 与安全", "代理服务", "网络与调优", "诊断与测试", "工具维护与恢复"):
            self.assertIn(label, text)

    def test_each_top_level_route_receives_the_current_mode(self):
        routes = self.stub_main_routes()
        self.assertEqual(self.run_menu(["1", "2", "3", "4", "5", "6", "0"]), 0)
        for route in routes.values():
            route.assert_called_once_with(demo=False, experimental=False)

    def test_home_reuses_overview_until_explicit_refresh(self):
        self.stub_main_routes()
        self.assertEqual(self.run_menu(["1", "2", "3", "R", "0"]), 0)
        self.assertEqual(self.overview.call_count, 2)
        self.collect.assert_not_called()

    def test_modification_can_be_enabled_then_disabled_without_restart(self):
        routes = self.stub_main_routes()
        self.assertEqual(self.run_menu(["M", "ENABLE", "1", "M", "1", "0"]), 0)
        self.assertEqual(routes["system_menu"].call_args_list,
                         [call(demo=False, experimental=True), call(demo=False, experimental=False)])

    def test_cancelled_mode_confirmation_stays_readonly(self):
        routes = self.stub_main_routes()
        self.assertEqual(self.run_menu(["m", "no", "1", "0"]), 0)
        routes["system_menu"].assert_called_once_with(demo=False, experimental=False)

    def test_initial_modification_mode_can_be_disabled_immediately(self):
        routes = self.stub_main_routes()
        self.assertEqual(self.run_menu(["M", "1", "0"], experimental=True), 0)
        routes["system_menu"].assert_called_once_with(demo=False, experimental=False)

    def test_demo_home_never_collects_real_status(self):
        routes = self.stub_main_routes()
        self.collect.side_effect = AssertionError("demo called real status collector")
        self.overview.side_effect = AssertionError("demo called real overview collector")
        self.assertEqual(self.run_menu(["M", "1", "R", "0"], demo=True), 0)
        routes["system_menu"].assert_called_once_with(demo=True, experimental=False)
        self.collect.assert_not_called()
        self.overview.assert_not_called()

    def test_eof_at_home_or_enable_confirmation_exits_cleanly(self):
        for answers in ([EOFError()], ["M", EOFError()]):
            with self.subTest(answers=answers):
                self.assertEqual(self.run_menu(answers), 0)

    def test_demo_status_uses_no_live_collector(self):
        self.collect.side_effect = AssertionError("demo called real status collector")
        with patch.object(cli.status, "render", side_effect=lambda data: json.dumps(data, ensure_ascii=False)):
            cli.show_status("ssh", demo=True)
        self.collect.assert_not_called()
        self.assertIn("演示", self.output.getvalue())

    def test_status_view_chooses_summary_or_detail_from_same_collector(self):
        with patch.object(cli.status, "render_summary", return_value="summary") as summary, \
                patch.object(cli.status, "render", return_value="details") as detail:
            cli.show_status("ssh", summary=True)
            cli.show_status("ssh")
        self.assertEqual(self.collect.call_args_list, [call("ssh"), call("ssh")])
        summary.assert_called_once_with(payload("ssh"))
        detail.assert_called_once_with(payload("ssh"))


class CLICompatibilityTest(unittest.TestCase):
    LEGACY_SECTIONS = ("system", "packages", "panel", "bbr", "tuning", "ssh", "ufw", "fail2ban", "hy2",
                       "swap", "timezone", "dns", "network", "security", "common", "all")

    def test_all_existing_status_sections_and_aliases_keep_json_cli(self):
        for section in dict.fromkeys((*self.LEGACY_SECTIONS, *cli.status.SECTIONS, *cli.status.ALIASES)):
            with self.subTest(section=section), \
                    patch.object(cli.platform, "system", return_value="Linux"), \
                    patch.object(cli.status, "collect", return_value=payload(section)) as collect, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                result = cli.main(["status", section, "--json"])
                self.assertEqual(result, 0)
                self.assertEqual(json.loads(output.getvalue()), payload(section))
                collect.assert_called_once_with(section)

    def test_doctor_json_remains_one_clean_document(self):
        with patch.object(cli.platform, "system", return_value="Linux"), \
                patch.object(cli.status, "collect", return_value=payload("all")) as collect, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["doctor", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue()), payload("all"))
        collect.assert_called_once_with("all")

    def test_demo_json_aliases_never_touch_host(self):
        with patch.object(cli.status, "collect", side_effect=AssertionError("demo host query")):
            for section in (*cli.status.ALIASES, "all"):
                with self.subTest(section=section), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(cli.main(["status", section, "--demo", "--json"]), 0)
                    data = json.loads(output.getvalue())
                    self.assertTrue(data["demo"])
                    self.assertEqual(data["section"], section)

    def test_version_command_and_flag_keep_working(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(["version"]), 0)
        self.assertEqual(output.getvalue().strip(), cli.__version__)
        with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as exited:
            cli.main(["--version"])
        self.assertEqual(exited.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), cli.__version__)

    def test_network_report_renders_real_status_metadata_and_details(self):
        with patch.object(cli.checks, "network_report", return_value="network detail sentinel") as report, \
                patch.object(cli.status.platform, "node", return_value="ci-host"), \
                patch.object(cli.status, "collect_selected", wraps=cli.status.collect_selected) as collect, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            cli.show_report("network")
        text = output.getvalue()
        report.assert_called_once_with()
        collect.assert_called_once_with((), section="network-details")
        self.assertIn("network detail sentinel", text)
        self.assertIn("网络监听与实际队列", text)
        self.assertRegex(text, r"状态生成时间：\d{4}-\d{2}-\d{2}T[^\n]+；主机：ci-host")


class OperationRoutingTest(unittest.TestCase):
    # Backend calls remain mocked: these tests cannot change the host or probe a network.
    CASES = (
        ("system_menu", "2", [], cli.swap, "change", (), {"experimental": True}),
        ("system_menu", "3", [], cli.swap, "change", (), {"remove": True, "experimental": True}),
        ("system_menu", "4", [], cli.common, "timezone_change", (), {"experimental": True}),
        *(("packages_menu", str(index), [], cli.packages, "run_action", (action,), {"experimental": True})
          for index, action in enumerate(("update", "upgrade", "base", "network", "monitor", "security"), 1)),
        ("ssh_menu", "1", ["2222", "yes"], cli.ssh, "change", (),
         {"new_port": 2222, "open_firewall": True, "experimental": True}),
        ("ssh_menu", "2", ["22"], cli.ssh, "change", (), {"remove_port": 22, "experimental": True}),
        ("ssh_menu", "3", [], cli.ssh, "change", (), {"key_only": True, "experimental": True}),
        ("ufw_menu", "1", ["20000", "20100", "udp"], cli.firewall, "allow", (20000, 20100, "udp"), {"experimental": True}),
        ("ufw_menu", "2", [], cli.firewall, "enable", (), {"experimental": True}),
        ("ufw_menu", "3", ["443", "", "tcp", "YES"], cli.firewall.FirewallManager, "delete", (443, 443, "tcp"), {}),
        ("fail2ban_menu", "1", [], cli.fail2ban, "configure", (), {"experimental": True}),
        ("fail2ban_menu", "2", ["192.0.2.10"], cli.fail2ban, "unban", ("192.0.2.10",), {"experimental": True}),
        ("panel_menu", "1", [], cli.panel, "install", (), {"experimental": True}),
        ("hy2_menu", "1", ["eth0", "20000", "20100", "443", "46", "yes"], cli.hy2, "change",
         (cli.hy2.HopSpec("eth0", 20000, 20100, 443, ("ip", "ip6")),), {"allow_firewall": True, "experimental": True}),
        ("hy2_menu", "2", [], cli.hy2, "change", (), {"remove": True, "experimental": True}),
        ("bbr_menu", "1", [], cli.bbr, "change", (), {"experimental": True}),
        ("bbr_menu", "2", [], cli.bbr, "change", (), {"restore": True, "experimental": True}),
        ("tuning_menu", "1", [], cli.tuning, "change", ("conservative",), {"experimental": True}),
        ("tuning_menu", "2", [], cli.tuning, "change", ("proxy",), {"experimental": True}),
        ("tuning_menu", "3", ["1000", "80"], cli.tuning, "change", ("buffer",),
         {"bandwidth_mbps": 1000, "rtt_ms": 80, "experimental": True}),
        ("tuning_menu", "4", [], cli.tuning, "change", ("proxy",), {"fastopen": True, "experimental": True}),
        ("tuning_menu", "5", [], cli.tuning, "change", (), {"restore": True, "experimental": True}),
        *(("external_menu", str(index), [], cli.external, "run", (key,), {"experimental": True})
          for index, key in enumerate(("nq", "tq", "ipquality", "netquality", "yabs"), 1)),
    )
    CHILD_ROUTES = (
        ("system_menu", "1", "packages_menu"),
        ("security_menu", "1", "ssh_menu"), ("security_menu", "2", "ufw_menu"),
        ("security_menu", "3", "fail2ban_menu"),
        ("proxy_menu", "1", "panel_menu"), ("proxy_menu", "2", "hy2_menu"),
        ("network_menu", "3", "bbr_menu"), ("network_menu", "4", "tuning_menu"),
        ("test_menu", "6", "external_menu"),
    )

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.show = self.stack.enter_context(patch.object(cli, "show_status"))
        self.preflight = self.stack.enter_context(patch.object(cli.packages, "preflight", return_value=None))
        self.stack.enter_context(patch.object(cli.status, "collect", side_effect=AssertionError("unexpected live collector")))
        self.stack.enter_context(patch.object(cli.checks, "run_check", side_effect=AssertionError("unexpected system command")))
        self.backends = {}
        for _, _, _, owner, name, _, _ in self.CASES:
            key = (owner, name)
            if key not in self.backends:
                self.backends[key] = self.stack.enter_context(patch.object(owner, name, return_value=0))

    def test_group_routes_retain_all_existing_function_families(self):
        for parent, number, child in self.CHILD_ROUTES:
            with self.subTest(parent=parent, child=child), patch.object(cli, child) as route, \
                    patch("builtins.input", side_effect=[number, "0"]):
                getattr(cli, parent)(demo=False, experimental=True)
                route.assert_called_once_with(demo=False, experimental=True)

    def test_each_modification_route_reaches_its_original_backend(self):
        for menu, number, answers, owner, name, args, kwargs in self.CASES:
            with self.subTest(menu=menu, number=number):
                for backend in self.backends.values():
                    backend.reset_mock()
                with patch("builtins.input", side_effect=[number, *answers, "0"]):
                    getattr(cli, menu)(demo=False, experimental=True)
                self.backends[(owner, name)].assert_called_once_with(*args, **kwargs)
                for other_key, other in self.backends.items():
                    if other_key != (owner, name):
                        other.assert_not_called()

    def test_success_refreshes_module_details_but_nonzero_result_does_not(self):
        cases = (
            ("packages_menu", "1", cli.packages, "run_action", "packages"),
            ("system_menu", "2", cli.swap, "change", "swap"),
            ("system_menu", "4", cli.common, "timezone_change", "timezone"),
            ("ssh_menu", "3", cli.ssh, "change", "ssh"),
            ("ufw_menu", "2", cli.firewall, "enable", "ufw"),
            ("fail2ban_menu", "1", cli.fail2ban, "configure", "fail2ban"),
            ("panel_menu", "1", cli.panel, "install", "panel"),
            ("hy2_menu", "2", cli.hy2, "change", "hy2"),
            ("bbr_menu", "1", cli.bbr, "change", "bbr"),
            ("tuning_menu", "1", cli.tuning, "change", "tuning"),
        )
        for menu, number, owner, method, section in cases:
            for code in (0, 1, 2):
                with self.subTest(menu=menu, result=code):
                    self.show.reset_mock()
                    backend = self.backends[(owner, method)]
                    backend.reset_mock()
                    backend.return_value = code
                    with patch("builtins.input", side_effect=[number, "0"]):
                        getattr(cli, menu)(demo=False, experimental=True)
                    backend.assert_called_once()
                    details = [entry for entry in self.show.call_args_list if not entry.kwargs.get("summary", False)]
                    self.assertEqual(details, [call(section)] if code == 0 else [])

    def test_demo_and_readonly_block_backends_before_parameter_prompts(self):
        for demo, experimental in ((False, False), (True, False), (True, True)):
            for menu, number, _, _, _, _, _ in self.CASES:
                with self.subTest(menu=menu, number=number, demo=demo, experimental=experimental):
                    for backend in self.backends.values():
                        backend.reset_mock()
                    # Only the action choice and Back are supplied: asking for any
                    # mutation parameter before the mode gate fails this sequence.
                    with patch("builtins.input", side_effect=[number, "0"]):
                        getattr(cli, menu)(demo=demo, experimental=experimental)
                    for backend in self.backends.values():
                        backend.assert_not_called()
        self.preflight.assert_not_called()

    def test_ufw_preflight_refusal_happens_before_parameters_or_manager(self):
        self.preflight.return_value = "需要 root 和交互式终端"
        for number in ("1", "3"):
            with self.subTest(number=number), patch.object(cli.firewall, "FirewallManager") as manager, \
                    patch("builtins.input", side_effect=[number, "0"]) as read:
                cli.ufw_menu(demo=False, experimental=True)
                self.assertEqual(read.call_count, 2)
                manager.assert_not_called()
        for backend in self.backends.values():
            backend.assert_not_called()

    def test_leaf_eof_and_bad_integer_do_not_modify_anything(self):
        for menu, answers in (("ssh_menu", ["1", "not-a-port", "0"]),
                              ("ufw_menu", ["1", "bad", "0"]),
                              ("hy2_menu", ["1", "eth0", "bad", "0"]),
                              ("tuning_menu", ["3", "bad", "0"]),
                              ("ssh_menu", [EOFError()])):
            with self.subTest(menu=menu, answers=answers), patch("builtins.input", side_effect=answers):
                getattr(cli, menu)(demo=False, experimental=True)
        for backend in self.backends.values():
            backend.assert_not_called()

    def test_demo_diagnostics_never_probe_or_download(self):
        with patch.object(cli.bench, "machine_report", side_effect=AssertionError("machine probe")), \
                patch.object(cli.bench, "network_report", side_effect=AssertionError("network probe")), \
                patch.object(cli.bench, "route_report", side_effect=AssertionError("route probe")), \
                patch.object(cli.bench, "bandwidth_report", side_effect=AssertionError("download")), \
                patch("builtins.input", side_effect=["2", "3", "4", "5", "0"]):
            cli.test_menu(demo=True, experimental=True)

    def test_readonly_diagnostics_and_external_preview_remain_available(self):
        for number, method in (("2", "machine_report"), ("3", "network_report"), ("4", "route_report")):
            with self.subTest(number=number), patch.object(cli.bench, method, return_value="report") as run, \
                    patch("builtins.input", side_effect=[number, "0"]):
                cli.test_menu(demo=False, experimental=False)
                run.assert_called_once_with()
        with patch.object(cli.external, "preview") as preview, \
                patch("builtins.input", side_effect=["6", "nq", "0"]):
            cli.external_menu(demo=False, experimental=False)
            preview.assert_called_once_with("nq")

    def test_bandwidth_still_requires_confirmation_and_passes_size(self):
        with patch.object(cli.bench, "bandwidth_report", return_value="report") as run, \
                patch("builtins.input", side_effect=["5", "10", "NO", "5", "25", "YES", "0"]):
            cli.test_menu(demo=False, experimental=False)
            run.assert_called_once_with(25)

    def test_demo_external_preview_never_downloads(self):
        with patch.object(cli.external, "preview", side_effect=AssertionError("preview download")), \
                patch("builtins.input", side_effect=["6", "0"]):
            cli.external_menu(demo=True, experimental=True)

    def test_managed_modules_share_s_for_full_status(self):
        menus = ("system_menu", "packages_menu", "security_menu", "ssh_menu", "ufw_menu", "fail2ban_menu",
                 "proxy_menu", "panel_menu", "hy2_menu", "network_menu", "bbr_menu", "tuning_menu")
        for name in menus:
            with self.subTest(menu=name):
                self.show.reset_mock()
                with patch("builtins.input", side_effect=["S", "0"]):
                    getattr(cli, name)(demo=False, experimental=False)
                details = [entry for entry in self.show.call_args_list
                           if not entry.kwargs.get("summary", False)]
                self.assertTrue(details, f"{name} has no full status route")

    def test_full_status_menu_keeps_all_existing_sections(self):
        sections = ("all", "system", "packages", "panel", "bbr", "ssh", "ufw", "fail2ban", "hy2", "common", "tuning")
        with patch("builtins.input", side_effect=[*(str(n) for n in range(1, 12)), "0"]):
            cli.status_menu(demo=False)
        self.assertEqual(self.show.call_args_list, [call(name, demo=False) for name in sections])

    def test_network_details_and_dns_still_work_readonly(self):
        with patch.object(cli, "show_report") as report, \
                patch("builtins.input", side_effect=["1", "2", "0"]):
            cli.network_menu(demo=False, experimental=False)
        report.assert_called_once_with("network")
        self.assertIn(call("dns"), self.show.call_args_list)

    def test_diagnostic_status_and_maintenance_navigation_remain_available(self):
        with patch.object(cli, "status_menu") as route, patch("builtins.input", side_effect=["1", "0"]):
            cli.test_menu(demo=True, experimental=False)
            route.assert_called_once_with(demo=True)
        with patch.object(cli, "_installation_info") as installation, \
                patch.object(cli, "_upgrade_info") as upgrade, \
                patch.object(cli, "_uninstall_info") as uninstall, \
                patch.object(cli, "_recovery_info") as recovery, \
                patch("builtins.input", side_effect=["1", "2", "3", "4", "0"]):
            cli.maintenance_menu(demo=False, experimental=False)
        for action in (installation, upgrade, uninstall, recovery):
            action.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
