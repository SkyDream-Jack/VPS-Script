"""Bounded history recovery for SSH, UFW and the project's Fail2ban jail.

These adapters never restore arbitrary paths, flush firewall tables, or replay
commands stored in a backup. Unsupported reverse operations remain inspectable
backups, with an explicit reason instead of an unsafe automatic restore.
"""

import hashlib
import os
from pathlib import Path
import pwd
import re

from . import backup, fail2ban, firewall, ssh


def _shape(snapshot, keys):
    if not isinstance(snapshot, dict) or set(snapshot) != set(keys):
        raise backup.BackupFailure("历史访问配置的结构无效")


def _files(snapshot, paths):
    files = snapshot.get("files")
    if not isinstance(files, dict) or set(files) != set(paths):
        raise backup.BackupFailure("历史文件清单与模块白名单不一致")
    for item in files.values():
        backup.decode_file(item)
    return files


def _same(adapter, expected):
    if adapter.capture() != expected:
        raise backup.BackupFailure("当前状态与所选历史记录的变更后状态不同，拒绝覆盖后续或外部修改")


def _verify_ssh():
    try:
        return input("历史 SSH 配置已应用；通过保留端口建立独立 SSH 会话后输入 VERIFIED：").strip() == "VERIFIED"
    except EOFError:
        return False


class SSHAdapter:
    paths = ("etc/ssh/sshd_config.d/00-vps-script.conf",)
    scope = "仅恢复本项目 SSH drop-in；恢复也使用 180 秒定时回退和第二会话验证"
    limitations = "不恢复其他 SSH 文件、账户密钥、云防火墙；历史配置必须保留当前会话端口；定时回退不保证跨重启或一定成功"

    def __init__(self, root=Path("/"), manager=None, verify=None):
        self.root = Path(root)
        self.manager = manager or ssh.SSHManager(self.root)
        self.verify = verify or _verify_ssh

    def capture(self):
        context = {}
        for path in (self.manager.base, *sorted(self.manager.dropins.glob("*.conf"))):
            if path == self.manager.target:
                continue
            context[path.relative_to(self.root).as_posix()] = hashlib.sha256(self.manager.files._read_regular(path)).hexdigest()
        connection = os.environ.get("SSH_CONNECTION", "").split()
        firewall.ssh_session_port(" ".join(connection))
        user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
        sshd, systemctl, ss = (self.manager.command(name) for name in ("sshd", "systemctl", "ss"))
        effective, ports = self.manager.effective(sshd, user, connection[0])
        listening = ssh.listening_ports(self.manager.run((ss, "-H", "-l", "-t", "-n")).stdout)
        runtime = {"service": self.manager.service(systemctl), "effective_ports": sorted(ports),
                   "listening_ports": sorted(ports & listening),
                   "effective_auth": {key: effective.get(key, []) for key in (*ssh.AUTH, "permitrootlogin")}}
        return {"files": backup.snapshot_files(self.root, self.paths), "context": context, "runtime": runtime}

    def recovery_reason(self, before, after):
        for snapshot in (before, after):
            _shape(snapshot, ("files", "context", "runtime"))
            files = _files(snapshot, self.paths)
            saved = files[self.paths[0]]
            expected_uid = 0 if self.root == Path("/") else os.geteuid()
            if saved["exists"] and (saved["uid"] != expected_uid or (self.root == Path("/") and saved["gid"] != 0)):
                return "历史 SSH 文件的所有者不符合恢复要求"
            try:
                ssh.read_managed(backup.decode_file(files[self.paths[0]]))
            except ssh.SSHFailure:
                return "历史文件不是本项目可识别的 SSH 配置"
        if before["context"] != after["context"]:
            return "其他 SSH 配置在变更期间发生变化，不能自动恢复"
        return None

    def restore(self, before, after):
        reason = self.recovery_reason(before, after)
        if reason:
            raise backup.BackupFailure(reason)
        desired = backup.decode_file(before["files"][self.paths[0]])
        expected = backup.decode_file(after["files"][self.paths[0]])
        mode = before["files"][self.paths[0]].get("mode", 0o644)
        connection = os.environ.get("SSH_CONNECTION", "").split()
        current_port = firewall.ssh_session_port(" ".join(connection))
        user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
        _, key_only = ssh.read_managed(desired)
        print("历史恢复可能重新允许密码/键盘交互认证；恢复范围仅为本项目 SSH 配置。")
        if key_only:
            print("恢复目标要求公钥登录；请确保当前账户已有可用公钥。")
        result = self.manager.restore_snapshot(expected, desired, mode, user=user, address=connection[0],
                                               current_port=current_port, verify=self.verify,
                                               precheck=lambda: _same(self, after))
        restored = self.capture()
        if restored != before:
            raise backup.BackupFailure("SSH 恢复命令完成，但文件或外部配置与目标不一致；请检查状态")
        return result + " Fail2ban 端口保护需随后单独刷新；不修改云防火墙。"


class UFWAdapter:
    paths = ("etc/default/ufw", "etc/ufw/ufw.conf", "etc/ufw/user.rules", "etc/ufw/user6.rules",
             "etc/ufw/before.rules", "etc/ufw/before6.rules", "etc/ufw/after.rules", "etc/ufw/after6.rules")
    mutable = frozenset(("etc/ufw/ufw.conf", "etc/ufw/user.rules", "etc/ufw/user6.rules"))
    scope = "可撤销本次新增的简单 allow；首次启用的恢复仅关闭 UFW，保留新增 allow 规则"
    limitations = "不 flush/覆盖规则表；禁止撤销当前活动 SSH 端口的放行；删除规则、复杂规则及规则顺序变化仅备份，不自动恢复"

    def __init__(self, root=Path("/"), manager=None):
        self.root = Path(root)
        self.manager = manager or firewall.FirewallManager(self.root)

    def capture(self):
        ufw = self.manager.command("ufw")
        state = self.manager.status(ufw)
        output = self.manager.run((ufw, "show", "added")).stdout
        if len(output.encode("utf-8")) > 262_144:
            raise backup.BackupFailure("UFW 规则清单过大，未执行变更")
        rules = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Added user rules"):
                continue
            if not line.startswith("ufw "):
                raise backup.BackupFailure("无法识别 UFW 已保存规则")
            rules.append(line)
        return {"files": backup.snapshot_files(self.root, self.paths), "state": state, "rules": rules}

    @staticmethod
    def _added_rule(before, after):
        old, new = before["rules"], after["rules"]
        if not isinstance(old, list) or not isinstance(new, list) or any(not isinstance(rule, str) for rule in (*old, *new)):
            raise backup.BackupFailure("UFW 历史规则列表无效")
        if len(new) != len(old) + 1 or new[:-1] != old:
            return None
        match = re.fullmatch(r"ufw allow ([0-9]{1,5})(?::([0-9]{1,5}))?/(tcp|udp)", new[-1])
        if not match:
            return None
        start, end, protocol = int(match[1]), int(match[2] or match[1]), match[3]
        firewall.port_rule(start, end, protocol)
        if new[-1] in old:
            return None
        return start, end, protocol

    def recovery_reason(self, before, after):
        for snapshot in (before, after):
            _shape(snapshot, ("files", "state", "rules"))
            _files(snapshot, self.paths)
            if snapshot["state"] not in ("active", "inactive"):
                raise backup.BackupFailure("UFW 历史状态无效")
        if any(before["files"][path] != after["files"][path] for path in self.paths if path not in self.mutable):
            return "UFW 默认策略或框架配置同时变化，不能自动恢复"
        added = self._added_rule(before, after)
        if before["state"] == "inactive" and after["state"] == "active":
            if before["rules"] == after["rules"] or (added and added[0] == added[1] and added[2] == "tcp"):
                return None
        if before["state"] == after["state"] and added:
            if before["files"]["etc/ufw/ufw.conf"] == after["files"]["etc/ufw/ufw.conf"]:
                return None
        return "仅支持撤销单次新增的简单 allow 或首次启用；删除/复杂规则/顺序变化不能自动恢复"

    def restore(self, before, after):
        reason = self.recovery_reason(before, after)
        if reason:
            raise backup.BackupFailure(reason)
        with self.manager.files.locked():
            _same(self, after)
            ufw = self.manager.command("ufw")
            if before["state"] == "inactive" and after["state"] == "active":
                print("恢复将关闭 UFW 防护，保留已有 allow 规则；不会删除规则或重置其他防火墙。")
                self.manager.run((ufw, "--force", "disable"))
                current = self.capture()
                if current["state"] != "inactive" or current["rules"] != after["rules"]:
                    raise backup.BackupFailure("关闭 UFW 后状态或已保存规则不符合预期")
                return "已恢复为 UFW inactive；新增 SSH allow 规则保留，防火墙防护已关闭。"
            start, end, protocol = self._added_rule(before, after)
            self.manager.guard_delete(start, end, protocol, after["state"])
            self.manager.run((ufw, "delete", "allow", firewall.port_rule(start, end, protocol)))
            current = self.capture()
            if current["state"] != before["state"] or current["rules"] != before["rules"]:
                raise backup.BackupFailure("撤销 allow 后状态或规则顺序与目标不符；请检查配置")
            return "已撤销本次新增 allow，原有规则顺序和 UFW 启用状态保持；未覆盖规则表。"


def _jail(data):
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
        port_match = re.search(r"^port = ([0-9,]+)$", text, re.MULTILINE)
        action_match = re.search(r"^banaction = ([a-z-]+)$", text, re.MULTILINE)
        if not port_match or not action_match:
            raise ValueError("missing fields")
        ports = tuple(int(value) for value in port_match[1].split(","))
        action = action_match[1]
        if data != fail2ban.jail_config(ports, action):
            raise ValueError("noncanonical jail")
    except (UnicodeError, ValueError, fail2ban.Fail2banFailure) as exc:
        raise backup.BackupFailure("历史 jail 不是本项目生成的完整配置") from exc
    return ports, action


class Fail2banAdapter:
    paths = ("etc/fail2ban/jail.d/50-vps-script-sshd.local",)
    scope = "恢复或移除本项目的 SSH jail 配置；保持 Fail2ban 服务，不恢复动态封禁列表"
    limitations = "其他活动 jail 存在时不自动重载；历史端口必须匹配当前 SSH，封禁动作必须兼容当前防火墙；解封 IP 不提供自动反向封禁"

    def __init__(self, root=Path("/"), manager=None):
        self.root = Path(root)
        self.manager = manager or fail2ban.Fail2banManager(self.root)

    def capture(self):
        client, systemctl = (self.manager.command(name) for name in ("fail2ban-client", "systemctl"))
        service = self.manager.run((systemctl, "is-active", "fail2ban.service"), check=False)
        if service.returncode != 0 or service.stdout.strip() != "active":
            raise backup.BackupFailure("Fail2ban 服务未运行，无法备份可恢复配置")
        names = fail2ban.jail_names(self.manager.run((client, "status")).stdout)
        return {"files": backup.snapshot_files(self.root, self.paths), "jails": sorted(names), "service": "active"}

    def recovery_reason(self, before, after):
        for snapshot in (before, after):
            _shape(snapshot, ("files", "jails", "service"))
            files = _files(snapshot, self.paths)
            config = backup.decode_file(files[self.paths[0]])
            try:
                _jail(config)
            except backup.BackupFailure:
                return "历史 jail 含非标准项目配置，已备份但不能自动重放"
            if snapshot["service"] != "active" or not isinstance(snapshot["jails"], list):
                return "历史 Fail2ban 服务状态不符合安全恢复条件"
            if any(name != fail2ban.JAIL for name in snapshot["jails"]):
                return "存在其他活动 jail，不能自动重载以免改变其他防护"
            if (config is not None) != (fail2ban.JAIL in snapshot["jails"]):
                return "项目 jail 文件与实际启用状态不一致，不能自动恢复"
        if before == after:
            return "配置未发生变化；动态封禁记录不属于可恢复内容"
        return None

    def restore(self, before, after):
        reason = self.recovery_reason(before, after)
        if reason:
            raise backup.BackupFailure(reason)
        candidate = _jail(backup.decode_file(before["files"][self.paths[0]]))
        with self.manager.files.locked():
            _same(self, after)
            self.manager._directory_ok()
            client = self.manager.command("fail2ban-client")
            if candidate:
                sshd = self.manager.command("sshd")
                ports = fail2ban.ssh_ports(self.manager.run((sshd, "-T")).stdout)
                if set(candidate[0]) != set(ports):
                    raise backup.BackupFailure("历史 jail 端口与当前 SSH 不一致；请先恢复 SSH 或重新刷新端口")
                if candidate[1] != self.manager._banaction():
                    raise backup.BackupFailure("历史封禁动作与当前防火墙不兼容，拒绝恢复")
            backup.restore_files(self.root, before["files"], after["files"], self.paths)
            try:
                self.manager.run((client, "-t"))
                self.manager.run((client, "reload"))
                if self.capture() != before:
                    raise backup.BackupFailure("Fail2ban 恢复后的项目配置或 jail 状态与目标不一致")
            except BaseException:
                try:
                    current = backup.snapshot_files(self.root, self.paths)
                    if current != before["files"]:
                        raise backup.BackupFailure("恢复期间项目 jail 已被其他操作修改")
                    backup.restore_files(self.root, after["files"], current, self.paths)
                    self.manager.run((client, "reload"))
                except Exception as exc:
                    print(f"Fail2ban 恢复失败且撤销恢复未完成；请检查服务与历史备份：{exc}")
                raise
        return "项目 Fail2ban jail 配置已恢复；未恢复历史封禁 IP、计数或剩余封禁时间。"


def get_adapter(module, root=Path("/")):
    adapters = {"ssh": SSHAdapter, "ufw": UFWAdapter, "fail2ban": Fail2banAdapter}
    try:
        return adapters[module](root)
    except KeyError as exc:
        raise backup.BackupFailure(f"不支持的访问配置模块：{module}") from exc
