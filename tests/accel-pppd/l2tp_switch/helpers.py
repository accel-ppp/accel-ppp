import os
import re
import socket
import tempfile
import time

from common import accel_pppd_process, l2tp_peer_process, process


def log_path(cfg):
    """Log file of the daemon started from config path `cfg`."""
    return cfg + ".log"


def err_log_path(cfg):
    """File that [core] log-error= points at for config path `cfg`.

    log-file= and log-error= are independent log paths; module load
    failures (a bad name in [modules]) only appear in the latter.
    """
    return cfg + ".err"


def read_log(cfg):
    """Combined log-file= and log-error= output of the daemon started from
    `cfg`. Returns "" for files that do not exist yet.

    Logging goes to files rather than the Popen pipes, whose output came back
    empty in failing runs.
    """

    def _read(path):
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    log = _read(log_path(cfg))
    err = _read(err_log_path(cfg))
    if not err:
        return log
    return log + "\n--- log-error ---\n" + err


def start_instance(accel_pppd, accel_cmd, cli_port, l2tp_bind, l2tp_port, secret, extra="", thread_count=None, env=None, l2tp_extra=""):
    # The config path is needed to build the log paths inside the config
    # text, so it is reserved here instead of through config.make_tmp().
    fd, cfg = tempfile.mkstemp()
    os.close(fd)
    log = log_path(cfg)
    err_log = err_log_path(cfg)
    # triton starts one worker per CPU, so 1-vCPU CI legs run single-threaded.
    # L2TP_TEST_THREAD_COUNT=1 reproduces that locally.
    threads = thread_count or os.environ.get("L2TP_TEST_THREAD_COUNT")
    thread_line = f"thread-count={threads}" if threads else ""

    with open(cfg, "w") as f:
        f.write(
            f"""
    [modules]
    log_file
    log_syslog
    l2tp
    {extra}
    [core]
    log-error={err_log}
    {thread_line}
    [log]
    log-file={log}
    level=5
    copy=1
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind={l2tp_bind}
    port={l2tp_port}
    secret={secret}
    {l2tp_extra}
    [ppp]
    verbose=1
    """
        )
    # same output as config.make_tmp()
    print("make_tmp filename: " + cfg)

    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port, env=env
    )
    return started, thread, ctrl, cfg


def show_stat(accel_cmd, cli_port=2001):
    (exit_code, out, err) = process.run([accel_cmd, "-p", str(cli_port), "show stat"])
    assert exit_code == 0, f"show stat failed: {err}"
    return out


def tunnels_active(accel_cmd, cli_port=2001):
    """Global l2tp tunnel count from `show stat`.

    Used instead of the "[idle]" word of `l2tp switch show`, which does not
    distinguish an idle open tunnel from a closed one. Assumes at most one
    tunnel is open at a time.
    """
    out = show_stat(accel_cmd, cli_port)
    m = re.search(r"tunnels:\r?\n\s*starting: \d+\r?\n\s*active: (\d+)", out)
    assert m, f"couldn't parse tunnel count from show stat:\n{out}"
    return int(m.group(1))


def l2tp_finishing(accel_cmd, cli_port=2001):
    """(tunnels, control-channel sessions) in the "finishing" state of `show
    stat`. An object leaves it when its last reference drops, so a count that
    stays above zero means a leaked reference."""
    out = show_stat(accel_cmd, cli_port)
    found = []
    for section in ("tunnels", r"sessions \(control channels\)"):
        m = re.search(
            section + r":\r?\n\s*starting: \d+\r?\n\s*active: \d+\r?\n\s*finishing: (\d+)",
            out,
        )
        assert m, f"couldn't parse {section} from show stat:\n{out}"
        found.append(int(m.group(1)))
    return tuple(found)


def _cli_connection_inodes(cli_port):
    """Inodes of the TCP connections to the daemon's CLI port (its accepted
    sockets, not the listener), from /proc/net/tcp."""
    inodes = set()
    with open("/proc/net/tcp") as f:
        for line in list(f)[1:]:
            fields = line.split()
            local_port = int(fields[1].split(":")[1], 16)
            if local_port == cli_port and fields[3] != "0A":  # 0A: LISTEN
                inodes.add(fields[9])
    return inodes


def fd_count(pid, cli_port=None):
    """Number of open file descriptors of process `pid` (Linux /proc),
    excluding timerfds, which triton closes lazily after the timer is deleted.

    With `cli_port`, CLI connections are excluded too, since the daemon may
    not have closed the one from the last accel-cmd call yet.
    """
    cli_inodes = _cli_connection_inodes(cli_port) if cli_port else set()

    def counted(target):
        if "anon_inode:[timerfd]" in target:
            return False
        return not any(f"socket:[{ino}]" in target for ino in cli_inodes)

    return len([t for t in fd_targets(pid) if counted(t)])


def wait_udp_bound(port, timeout=10.0):
    """Waits until some process has `port` bound as a UDP socket.

    The peer harness needs a moment to open its socket. A switch that sends
    before that gets ICMP unreachable and abandons the tunnel. Returns True
    if bound."""
    needle = f":{port:04X} "
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with open("/proc/net/udp") as f:
            if any(needle in line.split(None, 2)[1] + " " for line in list(f)[1:]):
                return True
        time.sleep(0.05)
    return False


def fd_targets(pid):
    """What each open descriptor of process `pid` points at, for a failure
    message that says which one leaked."""
    targets = []
    for fd in sorted(os.listdir(f"/proc/{pid}/fd"), key=int):
        try:
            targets.append(f"{fd} -> {os.readlink(f'/proc/{pid}/fd/{fd}')}")
        except OSError:
            pass  # closed between listdir and readlink
    return targets


def wait_for_tunnels_active(accel_cmd, expected, timeout, cli_port=2001):
    """Polls `tunnels_active()` until it equals `expected`.

    Returns (found, elapsed-seconds, last-observed-count).
    """
    started = time.monotonic()
    n = None
    while time.monotonic() - started < timeout:
        n = tunnels_active(accel_cmd, cli_port)
        if n == expected:
            return True, time.monotonic() - started, n
        time.sleep(0.1)
    return False, time.monotonic() - started, n


def alloc_ports(n):
    """Returns `n` distinct loopback ports that are free for both UDP (L2TP)
    and TCP (accel-cmd CLI), so parallel runs do not collide.
    """
    held = []
    ports = []
    try:
        while len(ports) < n:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held += [udp, tcp]
            udp.bind(("127.0.0.1", 0))
            port = udp.getsockname()[1]
            try:
                tcp.bind(("127.0.0.1", port))
            except OSError:
                continue  # only UDP is free
            ports.append(port)
    finally:
        for sock in held:
            sock.close()
    return ports


# Timeouts of positive waits are only a patience bound, so they are scaled up
# to cover slow runners (QEMU, TSAN, loaded hosts). Override with
# L2TP_TEST_TIMEOUT_FACTOR.
WAIT_FACTOR = float(os.environ.get("L2TP_TEST_TIMEOUT_FACTOR", "6"))


def wait_for(predicate, timeout, interval=0.1, scale=True):
    """Polls `predicate()` until it returns a truthy value or `timeout`
    seconds (times WAIT_FACTOR, unless `scale` is False) pass. Returns the
    last value it returned.

    Pass scale=False for negative checks, where the full timeout is spent
    showing that a condition does not come true.
    """
    deadline = time.monotonic() + (timeout * WAIT_FACTOR if scale else timeout)
    value = predicate()
    while not value and time.monotonic() < deadline:
        time.sleep(interval)
        value = predicate()
    return value


def switch_show(accel_cmd, cli_port, check=True):
    """Output of `l2tp switch show` on the daemon listening on `cli_port`.

    With `check` a failing accel-cmd fails the assertion here. Pass
    check=False when polling a daemon that may not accept CLI connections yet.
    """
    (exit_code, out, err) = process.run([accel_cmd, "-p", str(cli_port), "l2tp switch show"])
    if check:
        assert exit_code == 0, f"l2tp switch show failed on port {cli_port}: {err}"
    return out


def wait_up(accel_cmd, cli_port, timeout=10.0):
    """Waits for a target to show "[up]" and returns the last `l2tp switch
    show` output (assert on "[up]" in it)."""
    out = [""]

    def up():
        out[0] = switch_show(accel_cmd, cli_port, check=False)
        return "[up]" in out[0]

    wait_for(up, timeout)
    return out[0]


def finish_harness(thread, ctrl, timeout):
    """Joins a peer-harness process, killing it if it outlives `timeout`.

    A --listen instance runs until --hold-seconds is up, so it has to be
    killed when a test ends early. Can be called more than once. Returns
    (returncode, stdout, stderr)."""
    rc, out, err = l2tp_peer_process.wait(thread, ctrl, timeout, kill_on_timeout=False)
    if rc is None:
        ctrl["process"].kill()
        thread.join(5.0)
        rc = ctrl["process"].returncode
        out, err = ctrl["out"], ctrl["err"]
    return rc, out, err
