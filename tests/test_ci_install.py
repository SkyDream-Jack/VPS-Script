import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("ci_install.py")
SPEC = importlib.util.spec_from_file_location("ci_install_helper", MODULE_PATH)
ci_install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_install)


class CheckoutInstallerCITest(unittest.TestCase):
    def test_pinned_baseline_uses_its_own_file_set(self):
        asset = (ci_install.PROJECT / "test-releases" / ci_install.BASELINE_VERSION
                 / f"vps-script-{ci_install.BASELINE_VERSION}.tar.gz")
        with tempfile.TemporaryDirectory() as directory:
            root, names = ci_install.unpack_baseline(asset.read_bytes(), Path(directory))
            self.assertEqual(ci_install.source_version(root), "0.5.1-dev")
            self.assertNotIn("src/vps_admin/backup.py", names)
            self.assertIn("src/vps_admin/backup.py", ci_install.INSTALLED_FILES)
            ci_install.verify_tree(root, root, names + ("install-local.sh", "bootstrap.py"))

    def test_changed_baseline_is_rejected_before_parsing_or_loading_code(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ci_install.tarfile, "open", side_effect=AssertionError("must not parse")), \
                self.assertRaisesRegex(RuntimeError, "pinned digest"):
            ci_install.unpack_baseline(b"tampered historical package", Path(directory))

    def test_canary_detects_backup_data_changes_in_private_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backups"
            ci_install.create_backup_canary(root)
            ci_install.verify_backup_canary(root)
            with self.assertRaisesRegex(RuntimeError, "existing backup storage"):
                ci_install.create_backup_canary(root)
            (root / ".ci-preservation-canary").write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "data changed"):
                ci_install.verify_backup_canary(root)

    def test_installed_backup_entrypoints_use_installed_modules_and_empty_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "backups"
            ci_install.create_backup_canary(root)
            ci_install.verify_backup_canary(root)
            (root / ".ci-preservation-canary").unlink()
            payload = {"schema": 1, "storage": str(root), "records": []}
            with patch.object(ci_install, "BACKUP_ROOT", root), \
                    patch.object(ci_install.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(payload))) as run:
                ci_install.verify_backup_entrypoints()
            import_command = run.call_args_list[0].args[0]
            self.assertEqual(import_command[:4], ("/usr/bin/python3", "-I", "-B", "-c"))
            self.assertEqual(import_command[-1], str(ci_install.DESTINATION / "src"))
            self.assertIn("backup, backup_access, backup_network", import_command[4])
            self.assertEqual(run.call_args_list[1].args[0], (str(ci_install.LAUNCHER), "history", "--json"))

    def test_installed_backup_entrypoints_reject_nonempty_or_created_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {"schema": 1, "storage": str(root), "records": [{"id": "unexpected"}]}
            with patch.object(ci_install, "BACKUP_ROOT", root), \
                    patch.object(ci_install.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(payload))), \
                    self.assertRaisesRegex(RuntimeError, "valid empty"):
                ci_install.verify_backup_entrypoints()
            payload["records"] = []
            (root / "unexpected").touch()
            with patch.object(ci_install, "BACKUP_ROOT", root), \
                    patch.object(ci_install.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(payload))), \
                    self.assertRaisesRegex(RuntimeError, "created unexpected"):
                ci_install.verify_backup_entrypoints()

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
