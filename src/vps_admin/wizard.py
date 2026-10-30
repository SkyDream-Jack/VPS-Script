"""Interactive initialization checklist; all mutations remain in existing modules.

No saved recipe is auto-resumed. Every visit reads current state and every step
requires an explicit choice. The durable source of change history is backup.py.
"""

from dataclasses import dataclass, field
import re
from typing import Callable

from . import backup, packages


@dataclass(frozen=True)
class Step:
    key: str
    title: str
    section: str
    run: Callable
    primary: tuple
    note: str


@dataclass
class Outcome:
    label: str = "未执行"
    problem: bool = False
    references: list = field(default_factory=list)


def select_steps(text, steps):
    """Validate the whole selection before doing anything; retain catalog order."""
    tokens = re.split(r"[\s,，]+", text.strip())
    allowed = {str(n) for n in range(1, len(steps) + 1)}
    if not tokens or any(token not in allowed for token in tokens):
        raise ValueError("请输入有效编号，以空格或逗号分隔；没有默认勾选项。")
    chosen = set(tokens)
    return tuple(step for n, step in enumerate(steps, 1) if str(n) in chosen)


def read_records(references):
    records = []
    for store, identifier in references:
        try:
            records.extend(backup.history(identifier, store=store)["records"])
        except (backup.BackupFailure, OSError) as exc:
            records.append({"id": identifier, "state": "invalid", "error": str(exc)})
    return records


def classify(step, code, records):
    """A zero exit code may mean cancellation or a partial ancillary operation."""
    if code == 130:
        return "已中断，需检查实际状态和原模块回退结果", True
    if code != 0 or any(record["state"] not in ("completed", "no_change") for record in records):
        return "未完成或记录待核实；可能已部分执行", True
    primary = [record for record in records
               if (record.get("module"), record.get("action")) == step.primary]
    if not primary:
        if records:
            return "仅有附属操作记录，主步骤未确认完成", True
        return "已取消或未执行（没有新增变更记录）", False
    if all(record["state"] == "no_change" for record in records):
        return "未发现受管理状态变化", False
    return "命令完成，实际效果仍需验证", False


def _print_records(references):
    for record in read_records(references):
        if record["state"] == "invalid":
            print(f"  记录 {record['id']} 无法核实；请查看 history 并保留备份。")
        else:
            ability = "可请求恢复" if record["restore_supported"] else "不可自动恢复"
            print(f"  记录 {record['id']} · {backup.STATES[record['state']]} · {ability}")


def _inspect(step, inspect, demo, *, detail=False):
    try:
        inspect(step.section if step else ("system", "ssh", "ufw", "fail2ban"),
                demo=demo, summary=not detail)
        return True
    except (OSError, ValueError) as exc:
        print(f"状态读取未完成：{exc}；可刷新重试，不能以旧摘要作为本次检查结果。")
        return False


def _execute(step, outcome):
    code = 1
    with backup.observe_records() as references:
        try:
            code = step.run()
        except KeyboardInterrupt:
            code = 130
        except EOFError:
            code = 130
        except (backup.BackupFailure, OSError, ValueError) as exc:
            print(f"操作未完成：{exc}")
        finally:
            outcome.references.extend(references)
    outcome.label, outcome.problem = classify(step, code, read_records(references))
    print(outcome.label)
    _print_records(references)
    return code


def run(steps, *, inspect, recover, demo=False, experimental=False):
    """Selectable plan and one-step-at-a-time execution; never an unattended batch."""
    selected, outcomes = (), {}
    exit_code = 0
    print("\n初始化向导 · " + ("演示模式" if demo else "修改模式" if experimental else "只读规划"))
    print("先选择步骤，再逐步查看状态、确认执行；未选步骤不会自动补做，没有一键全选或自动连续执行。")
    print("Q / 0 退出；步骤间可跳过。参数或确认过程中可用 Ctrl+C 退出，已经执行的修改不会自动撤销。")
    print("再次进入会重新检查实际状态，不自动重跑上次步骤；变更记录持久保存在 history 中。")
    print("软件安装/升级需原有 SNAPSHOT 声明，SSH/UFW 仍需第二会话验证；备份范围与各模块相同。")
    print("计划先处理 UFW，再安装/配置 Fail2ban；已有规则、服务或依赖不满足时仍停止，不自动停用现有防护。")
    try:
        _inspect(None, inspect, demo)
        while not selected:
            print("\n选择本次步骤（按下列顺序执行，可只选一项）：")
            for number, step in enumerate(steps, 1):
                print(f"{number}. {step.title}")
            print("R. 刷新概览  H. 备份记录与恢复  Q / 0. 退出")
            choice = input("编号（空格/逗号分隔，不默认选择）：").strip().lower()
            if choice in ("q", "0"):
                return 0
            if choice == "r":
                _inspect(None, inspect, demo)
            elif choice == "h":
                recover(demo=demo, experimental=experimental)
                _inspect(None, inspect, demo)
            else:
                try:
                    selected = select_steps(choice, steps)
                except ValueError as exc:
                    print(exc)
        outcomes = {step.key: Outcome() for step in selected}
        print("\n本次顺序：" + " → ".join(step.title for step in selected))
        for index, step in enumerate(selected, 1):
            outcome = outcomes[step.key]
            attempted = False
            print(f"\n[{index}/{len(selected)}] {step.title}\n{step.note}")
            _inspect(step, inspect, demo)
            while True:
                print("E. 执行本步  S. 跳过  R. 刷新状态  D. 详细状态  H. 备份记录与恢复  Q / 0. 退出")
                if attempted:
                    print("N. 进入下一步（不会自动执行）；再次 E 需要 RETRY 确认")
                choice = input("请选择：").strip().lower()
                if choice in ("q", "0"):
                    return exit_code
                if choice in ("s", "n") and (choice == "s" or attempted):
                    if outcome.problem and input("本步有未确认结果；输入 CONTINUE 才跳过并继续，其他内容留在本步：").strip() != "CONTINUE":
                        continue
                    if not attempted:
                        outcome.label = "已跳过"
                    break
                if choice in ("r", "d"):
                    _inspect(step, inspect, demo, detail=choice == "d")
                elif choice == "h":
                    recover(demo=demo, experimental=experimental)
                    _inspect(step, inspect, demo)
                elif choice == "e":
                    if demo:
                        outcome.label = "演示：未执行真实操作"
                        print(outcome.label)
                        attempted = True
                        continue
                    if not experimental:
                        print("只读规划不能修改；返回主菜单按 M 启用，或用 vps-script init --experimental 重新进入。")
                        continue
                    if attempted and input("请先核查当前状态与记录；输入 RETRY 重新进入本步，其他内容取消：").strip() != "RETRY":
                        continue
                    error = packages.preflight(experimental)
                    if error:
                        print(f"未执行：{error}")
                        outcome.label, outcome.problem = "前置检查未通过", True
                        exit_code = 1
                        attempted = True
                        continue
                    if not _inspect(step, inspect, demo):
                        outcome.label, outcome.problem = "执行前状态读取失败，未进入修改", True
                        exit_code = 1
                        attempted = True
                        continue
                    attempted = True
                    code = _execute(step, outcome)
                    if outcome.problem:
                        exit_code = 1
                    if code == 130:
                        exit_code = 130
                        return exit_code
                    if not _inspect(step, inspect, demo):
                        outcome.label += "；操作后状态读取失败"
                        outcome.problem = True
                        exit_code = 1
                else:
                    print("无效选择；不会自动执行或跳到下一步。")
        print("所选步骤已逐项处理；请检查下面的执行结果及外部连接。")
        return exit_code
    except EOFError:
        print("\n输入结束，已退出向导。")
        return exit_code
    except KeyboardInterrupt:
        print("\n已中断并退出向导；请检查实际状态和原模块回退结果。")
        return 130
    finally:
        print("\n本次向导结果（执行时结果，不代表当前业务或外部连接已验收）：")
        for step in selected:
            outcome = outcomes.get(step.key, Outcome())
            print(f"- {step.title}：{outcome.label}")
            _print_records(outcome.references)
        print("未执行步骤不会自动继续；退出不会撤销已完成修改。")
        print("可用 vps-script history 查看记录，或从主菜单 6 → 5 选择恢复；不是整机恢复。")
