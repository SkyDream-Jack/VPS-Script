import contextlib
import gzip
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.request

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import bootstrap
from release import build_release, prepare_test_version


class ReleaseTest(unittest.TestCase):
    def test_new_runtime_modules_are_in_download_build_and_installer_manifests(self):
        expected = {"backup.py", "backup_access.py", "backup_network.py"}
        installer = (PROJECT / "install-local.sh").read_text()
        modules_line = next(line for line in installer.splitlines() if line.startswith("modules=("))
        modules = set(shlex.split(modules_line[len("modules=("):-1]))
        self.assertTrue(expected.issubset(modules))
        for filename in expected:
            path = "src/vps_admin/" + filename
            self.assertIn(path, bootstrap.FILES)
            self.assertIn(path, build_release.FILES)

    def test_builder_is_reproducible_and_matches_bootstrap_whitelist(self):
        self.assertEqual(set(build_release.FILES), bootstrap.FILES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, digest = build_release.build("v0.1.0-dev", root / "a")
            second, digest2 = build_release.build("v0.1.0-dev", root / "b")
            self.assertEqual(digest, digest2)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            unpacked = bootstrap.unpack(first.read_bytes(), root / "unpacked")
            self.assertEqual((unpacked / "vps-admin").read_bytes(), (PROJECT / "vps-admin").read_bytes())
            self.assertTrue((unpacked / "vps-admin").stat().st_mode & 0o111)
            # Isolated import resolves only packaged project modules, not the
            # working checkout; -B keeps verification from altering the tree.
            code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                    "from vps_admin import backup, backup_access, backup_network")
            imported = subprocess.run((sys.executable, "-I", "-B", "-c", code, str(unpacked / "src")),
                                      cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(imported.stdout, "")
            self.assertFalse(tuple(unpacked.rglob("__pycache__")))

    def test_invalid_version_and_existing_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                build_release.build("../../evil", directory)
            build_release.build("v0.1.0-dev", directory)
            with self.assertRaises(FileExistsError):
                build_release.build("v0.1.0-dev", directory)

    def test_builder_rejects_symlinked_source_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            for name in build_release.FILES:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("sample", encoding="utf-8")
            package = source / "src/vps_admin"
            moved = root / "outside"
            package.rename(moved)
            package.symlink_to(moved, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "普通源码文件"):
                build_release.build("v0.1.0-dev", root / "out", source=source)

    def test_archive_with_symlink_is_rejected(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name in sorted(bootstrap.FILES):
                item = tarfile.TarInfo("vps-script/" + name)
                if name == "vps-admin":
                    item.type = tarfile.SYMTYPE
                    item.linkname = "/etc/passwd"
                    archive.addfile(item)
                else:
                    item.size = 1
                    archive.addfile(item, io.BytesIO(b"x"))
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, "链接"):
            bootstrap.unpack(buffer.getvalue(), directory)

    def test_compressed_bomb_is_rejected_before_tar_parsing(self):
        data = gzip.compress(b"x" * (bootstrap.MAX_TAR_BYTES + 1))
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, "tar 超过"):
            bootstrap.unpack(data, directory)

    def test_download_hash_mismatch_is_rejected(self):
        response = MagicMock()
        response.__enter__.return_value.read.side_effect = [b"wrong", b""]
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(bootstrap.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "不匹配"):
                bootstrap.download("v0.1.0-dev", "0" * 64)

    def test_redirect_to_other_origin_is_rejected(self):
        handler = bootstrap.ReleaseRedirect()
        request = urllib.request.Request(bootstrap.asset_url("v0.1.0-dev"))
        for target in ("http://raw.githubusercontent.com/x", "https://evil.example/x", "https://raw.githubusercontent.com:444/x"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "", {}, target)

    def test_preview_never_downloads(self):
        with patch.object(bootstrap, "download", side_effect=AssertionError("must not download")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = bootstrap.main(["v0.1.0-dev", "a" * 64, "--preview"])
        self.assertEqual(result, 0)
        self.assertIn("没有下载或安装", output.getvalue())

    def test_asset_url_uses_the_named_repository_and_version(self):
        self.assertEqual(bootstrap.asset_url("v0.2.0-dev"),
                         "https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/"
                         "test-releases/v0.2.0-dev/vps-script-v0.2.0-dev.tar.gz")

    def test_start_menu_after_successful_install_preserves_ssh_context(self):
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs["env"]))
            return subprocess.CompletedProcess(args, 0)
        with patch.object(bootstrap.platform, "system", return_value="Linux"), \
             patch.object(bootstrap.os, "geteuid", return_value=0), \
             patch.object(bootstrap.sys.stdin, "isatty", return_value=True), \
             patch.object(bootstrap.sys.stdout, "isatty", return_value=True), \
             patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 40000 192.0.2.2 22", "SUDO_USER": "tester"}), \
             patch("builtins.input", return_value="YES"), \
             patch.object(bootstrap, "download", return_value=b"test"), \
             patch.object(bootstrap, "unpack", return_value=Path("/tmp/test-project")), \
             patch.object(bootstrap.Path, "is_file", return_value=True), \
             patch.object(bootstrap.subprocess, "run", side_effect=run):
            result = bootstrap.main(["v0.2.0-dev", "a" * 64, "--start-menu"])
        self.assertEqual(result, 0)
        self.assertEqual(calls[1][0], ("/usr/local/bin/vps-script", "--experimental"))
        self.assertEqual(calls[1][1]["SSH_CONNECTION"], "192.0.2.1 40000 192.0.2.2 22")
        self.assertEqual(calls[1][1]["SUDO_USER"], "tester")

    def test_cancelled_install_does_not_start_menu(self):
        with patch.object(bootstrap.platform, "system", return_value="Linux"), \
             patch.object(bootstrap.os, "geteuid", return_value=0), \
             patch.object(bootstrap.sys.stdin, "isatty", return_value=True), \
             patch.object(bootstrap.sys.stdout, "isatty", return_value=True), \
             patch("builtins.input", return_value="YES"), \
             patch.object(bootstrap, "download", return_value=b"test"), \
             patch.object(bootstrap, "unpack", return_value=Path("/tmp/test-project")), \
             patch.object(bootstrap.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            self.assertEqual(bootstrap.main(["v0.2.0-dev", "a" * 64, "--start-menu"]), 1)
        self.assertEqual(run.call_count, 1)

    def test_short_install_script_pins_both_digests(self):
        script = prepare_test_version.install_script_for(
            "v0.3.0-dev", "a" * 64, "b" * 64)
        self.assertIn("VERSION='v0.3.0-dev'", script)
        self.assertIn("BOOTSTRAP_SHA='" + "a" * 64 + "'", script)
        self.assertIn("ARCHIVE_SHA='" + "b" * 64 + "'", script)
        self.assertIn("--upgrade --start-menu", script)
        self.assertIn("sha256(open(sys.argv[1]", script.replace("\n", ""))

    def test_document_uses_short_command_and_mentions_limits(self):
        document = prepare_test_version.document_for(
            "v0.3.0-dev", prepare_test_version.short_command("https://example.invalid/install.sh"),
            "a" * 64, "b" * 64, "c" * 64)
        self.assertIn('bash "$f"', document)
        self.assertNotIn('sudo bash', document)
        self.assertIn("短入口", document)
        self.assertIn("可丢弃", document)

    def test_one_line_entry_verifies_bootstrap_before_execution(self):
        body = b'outcome.append("verified")'
        digest = hashlib.sha256(body).hexdigest()
        command = prepare_test_version.command_for("v0.2.0-dev", digest, "a" * 64)
        args = shlex.split(command)
        self.assertEqual(args[:3], ["/usr/bin/python3", "-I", "-c"])
        self.assertEqual(args[4:], ["v0.2.0-dev", "a" * 64, "--upgrade", "--start-menu"])
        opener = MagicMock()
        opener.open.return_value.read.return_value = body
        namespace = {"outcome": []}
        with patch.object(sys, "platform", "linux"), \
             patch.object(os, "geteuid", return_value=0), \
             patch.object(sys.stdin, "isatty", return_value=True), \
             patch.object(sys.stdout, "isatty", return_value=True), \
             patch.object(urllib.request, "build_opener", return_value=opener):
            exec(args[3], namespace)
        self.assertEqual(namespace["outcome"], ["verified"])
        opener.open.assert_called_once_with(
            prepare_test_version.RELEASE_ROOT + "/v0.2.0-dev/bootstrap.py", timeout=20)
        self.assertIsNone(namespace["h"]().redirect_request(None, None, 302, "", {}, "https://evil.example/"))

    def test_one_line_entry_refuses_changed_bootstrap(self):
        command = prepare_test_version.command_for("v0.2.0-dev", "a" * 64, "b" * 64)
        code = shlex.split(command)[3]
        opener = MagicMock()
        opener.open.return_value.read.return_value = b'outcome.append("must not run")'
        namespace = {"outcome": []}
        with patch.object(sys, "platform", "linux"), \
             patch.object(os, "geteuid", return_value=0), \
             patch.object(sys.stdin, "isatty", return_value=True), \
             patch.object(sys.stdout, "isatty", return_value=True), \
             patch.object(urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(SystemExit, "校验失败"):
                exec(code, namespace)
        self.assertEqual(namespace["outcome"], [])

    def test_one_line_through_download_unpack_and_menu_without_network(self):
        bootstrap_data = (PROJECT / "bootstrap.py").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            asset, digest = build_release.build("v0.2.0-dev", Path(directory))
            archive = asset.read_bytes()
        command = prepare_test_version.command_for(
            "v0.2.0-dev", hashlib.sha256(bootstrap_data).hexdigest(), digest)
        args = shlex.split(command)
        urls, calls = [], []

        class FakeOpener:
            def open(self, request, timeout):
                url = request.full_url if hasattr(request, "full_url") else request
                urls.append(url)
                if url.endswith("/bootstrap.py"):
                    return io.BytesIO(bootstrap_data)
                if url == bootstrap.asset_url("v0.2.0-dev"):
                    return io.BytesIO(archive)
                raise AssertionError("unexpected network target")

        def run(command_args, **kwargs):
            calls.append(command_args)
            if command_args[0] == "/bin/bash":
                self.assertEqual(Path(command_args[1]).read_bytes(), (PROJECT / "install-local.sh").read_bytes())
            return subprocess.CompletedProcess(command_args, 0)

        with patch.object(sys, "argv", ["-c", *args[4:]]), \
             patch.object(sys, "platform", "linux"), \
             patch.object(os, "geteuid", return_value=0), \
             patch.object(sys.stdin, "isatty", return_value=True), \
             patch.object(sys.stdout, "isatty", return_value=True), \
             patch.object(urllib.request, "build_opener", return_value=FakeOpener()), \
             patch("builtins.input", return_value="YES"), \
             patch.object(bootstrap.platform, "system", return_value="Linux"), \
             patch.object(bootstrap.Path, "is_file", return_value=True), \
             patch.object(bootstrap.subprocess, "run", side_effect=run):
            with self.assertRaises(SystemExit) as result:
                exec(args[3], {"__name__": "__main__"})
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(len(urls), 2)
        self.assertEqual(calls[-1], ("/usr/local/bin/vps-script", "--experimental"))


if __name__ == "__main__":
    unittest.main()
