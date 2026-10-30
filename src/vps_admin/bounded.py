"""Bounded, non-shell subprocess output for audits and optional scans."""

from dataclasses import dataclass
import os
import selectors
import signal
import subprocess
import time


@dataclass(frozen=True)
class Result:
    code: object = None
    output: str = ""
    complete: bool = False
    reason: str = ""


def clean(text):
    """Untrusted logs, filenames and tool output must not control the terminal."""
    return "".join(c if (c.isprintable() or c in "\n\t") else f"\\u{ord(c):04x}" for c in str(text))


def run(args, *, timeout=5, limit=128 * 1024):
    process = None
    output = bytearray()
    reason = ""
    finished = False
    try:
        process = subprocess.Popen(tuple(args), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"})
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "超过时间限制，检查未完成"
                    break
                events = selector.select(min(remaining, 0.2))
                if not events:
                    continue
                chunk = os.read(process.stdout.fileno(), min(16384, limit + 1 - len(output)))
                if not chunk:
                    try:
                        process.wait(timeout=max(0.01, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        reason = "超过时间限制，检查未完成"
                    break
                output.extend(chunk)
                if len(output) > limit:
                    reason = "超过输出限制，检查未完成"
                    break
        finished = not reason
        return Result(process.poll(), clean(output[:limit].decode("utf-8", "replace")), finished, reason)
    except OSError as exc:
        return Result(reason=f"无法运行检查：{type(exc).__name__}")
    finally:
        if process is not None:
            # Also stop descendants holding the pipe open after the parent exits.
            if not finished or process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            process.stdout.close()
