import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("ci_install.py")
SPEC = importlib.util.spec_from_file_location("ci_install_helper", MODULE_PATH)
ci_install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_install)


class CheckoutInstallerCITest(unittest.TestCase):
    def test_missing_github_environment_stops_before_any_mutation(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(ci_install.platform, "system", return_value="Linux"), \
                patch.object(ci_install.os, "geteuid", return_value=0), \
                patch.object(ci_install, "prepare_runner_paths") as prepare, \
                patch.object(ci_install.build_release, "build") as build, \
                self.assertRaisesRegex(RuntimeError, "disposable GitHub-hosted"):
            ci_install.run_scenario("fresh")
        prepare.assert_not_called()
        build.assert_not_called()

    def test_existing_installation_is_never_used_as_test_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "existing"
            destination.mkdir()
            environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                           "GITHUB_WORKSPACE": str(ci_install.PROJECT)}
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(ci_install.platform, "system", return_value="Linux"), \
                    patch.object(ci_install.os, "geteuid", return_value=0), \
                    patch.object(ci_install, "DESTINATION", destination), \
                    self.assertRaisesRegex(RuntimeError, "existing installation"):
                ci_install.validate_ci_environment()

    def test_matching_version_does_not_hide_stale_installed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source, installed = Path(directory) / "checkout", Path(directory) / "installed"
            names = ("src/vps_admin/__init__.py", "src/vps_admin/example.py")
            for root in (source, installed):
                (root / "src/vps_admin").mkdir(parents=True)
                (root / names[0]).write_text('__version__ = "0.5.2-dev"\n', encoding="utf-8")
                (root / names[1]).write_text("same bytes\n", encoding="utf-8")
            ci_install.verify_tree(source, installed, names)
            (installed / names[1]).write_text("stale bytes\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Installed bytes differ"):
                ci_install.verify_tree(source, installed, names)

    def test_obsolete_files_fail_upgrade_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            source, installed = Path(directory) / "checkout", Path(directory) / "installed"
            name = "src/vps_admin/__init__.py"
            for root in (source, installed):
                (root / "src/vps_admin").mkdir(parents=True)
                (root / name).write_text('__version__ = "0.5.2-dev"\n', encoding="utf-8")
            (installed / "obsolete.py").write_text("old version\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Installed file set differs"):
                ci_install.verify_tree(source, installed, (name,))


if __name__ == "__main__":
    unittest.main()
