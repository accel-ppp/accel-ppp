"""State dump of an accel-pppd that does not exit when it should.

A CI failure of the form "did not exit after ..." says nothing about why. The
dump is printed (so pytest shows it with the failure) before the harness kills
the daemon: its threads, what they block on, its descriptors, the CLI view and
the log tail. Every part is best effort and bounded; none can fail the test.
"""

import os
import time
from subprocess import TimeoutExpired

from common import process

# per accel-cmd call: a daemon that hangs may not answer it at all
CLI_DUMP_TIMEOUT = 5.0
LOG_TAIL_LINES = 150
CLI_COMMANDS = ("show sessions", "show stat", "l2tp switch show")


def _read(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except OSError as e:
        return f"<unreadable: {e.strerror}>"


def _threads(pid):
    lines = []
    task_dir = f"/proc/{pid}/task"
    try:
        tids = sorted(os.listdir(task_dir), key=int)
    except OSError as e:
        return [f"<no {task_dir}: {e.strerror}>"]
    for tid in tids:
        base = f"{task_dir}/{tid}"
        lines.append(
            f"tid {tid} comm={_read(base + '/comm')} wchan={_read(base + '/wchan')}"
            f" syscall={_read(base + '/syscall')}"
        )
        stack = _read(base + "/stack")
        if stack and not stack.startswith("<"):
            lines.append("  stack: " + stack.replace("\n", "\n         "))
    return lines


def _fds(pid):
    fd_dir = f"/proc/{pid}/fd"
    try:
        names = sorted(os.listdir(fd_dir), key=int)
    except OSError as e:
        return [f"<no {fd_dir}: {e.strerror}>"]
    out = []
    for name in names:
        try:
            out.append(f"{name} -> {os.readlink(fd_dir + '/' + name)}")
        except OSError:
            continue
    return out


def _cli(accel_cmd, cli_port, command):
    argv = [accel_cmd]
    if cli_port is not None:
        argv += ["-p", str(cli_port)]
    argv.append(command)
    try:
        rc, out, err = process.run(argv, timeout=CLI_DUMP_TIMEOUT)
    except TimeoutExpired:
        return f"<no reply within {CLI_DUMP_TIMEOUT:.0f}s>"
    except OSError as e:
        return f"<cannot run: {e}>"
    return f"rc={rc}\n{out.strip()}\n{err.strip()}".strip()


def config_path(popen):
    """The -c<path> argument the daemon was started with."""
    for arg in getattr(popen, "args", None) or []:
        if isinstance(arg, str) and arg.startswith("-c"):
            return arg[2:]
    return None


def _log_tail(cfg):
    if not cfg:
        return "<config path unknown>"
    parts = []
    for suffix in (".log", ".err"):
        text = _read(cfg + suffix)
        if text:
            tail = text.splitlines()[-LOG_TAIL_LINES:]
            parts.append(f"--- {cfg + suffix} (last {len(tail)} lines) ---\n" + "\n".join(tail))
    return "\n".join(parts) or "<no log output>"


def dump_logs(popen, reason):
    """Prints the log tails of an already exited daemon `popen`: its stderr
    pipe is often empty for an abort() (the BUG: lines go to log-error=)."""
    print(f"===== accel-pppd {popen.pid} logs: {reason} =====")
    print(_log_tail(config_path(popen)))
    print(f"===== end of accel-pppd {popen.pid} logs =====")


def dump(popen, accel_cmd, cli_port, reason):
    """Prints the state of the still running daemon `popen`."""
    pid = popen.pid
    print(f"===== accel-pppd {pid} hang diagnostics: {reason} ({time.strftime('%H:%M:%S')}) =====")
    print("threads:")
    for line in _threads(pid):
        print("  " + line)
    print("open fds:")
    for line in _fds(pid):
        print("  " + line)
    for command in CLI_COMMANDS:
        print(f"accel-cmd {command!r}:\n  " + _cli(accel_cmd, cli_port, command).replace("\n", "\n  "))
    print(_log_tail(config_path(popen)))
    print(f"===== end of accel-pppd {pid} diagnostics =====")
