"""The harness must notice a daemon that exits badly or a command that hangs.

Uses a fake accel-pppd/accel-cmd pair so no real daemon (or sanitizer) is
involved: the fake daemon runs until the fake accel-cmd gets "shutdown hard",
then exits with the status given in its environment.
"""

import os
import stat
import subprocess
import sys
import time

import pytest
from common import accel_pppd_process, l2tp_peer_process, process

pytestmark = pytest.mark.l2tp_switch

FAKE_PPPD = """#!{py}
import os, sys, time
flag = os.environ["FAKE_FLAG"]
while not os.path.exists(flag):
    time.sleep(0.02)
sys.stderr.write("==1==ERROR: LeakSanitizer: detected memory leaks\\n")
sys.exit(int(os.environ["FAKE_EXIT"]))
"""

FAKE_CMD = """#!{py}
import os, sys, time
if "shutdown hard" in sys.argv:
    open(os.environ["FAKE_FLAG"], "w").close()
elif os.environ.get("FAKE_HANG") and "show version" not in sys.argv:
    time.sleep(600)
"""


def _script(path, template):
    path.write_text(template.format(py=sys.executable))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture()
def fake(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_FLAG", str(tmp_path / "stop"))
    return (
        _script(tmp_path / "pppd", FAKE_PPPD),
        _script(tmp_path / "cmd", FAKE_CMD),
    )


def _run_daemon(fake, exit_status, monkeypatch, check_exit=True):
    monkeypatch.setenv("FAKE_EXIT", str(exit_status))
    pppd, cmd = fake
    started, thread, ctrl = accel_pppd_process.start(
        pppd, [], cmd, 5.0, env=dict(os.environ)
    )
    assert started
    try:
        accel_pppd_process.end(thread, ctrl, cmd, 5.0, check_exit=check_exit)
    finally:
        assert ctrl["returncode"] is not None
    return ctrl


def test_clean_exit_passes(fake, monkeypatch):
    ctrl = _run_daemon(fake, 0, monkeypatch)
    assert ctrl["returncode"] == 0 and not ctrl["killed"]


def test_nonzero_exit_fails(fake, monkeypatch):
    with pytest.raises(AssertionError, match="exited with status 23"):
        _run_daemon(fake, 23, monkeypatch)


def test_nonzero_exit_is_recorded_without_check(fake, monkeypatch):
    ctrl = _run_daemon(fake, 23, monkeypatch, check_exit=False)
    assert ctrl["returncode"] == 23


def test_end_is_strict_by_default_in_this_package(fake, monkeypatch):
    # the package conftest swaps in a strict end(); no check_exit passed
    monkeypatch.setenv("FAKE_EXIT", "7")
    pppd, cmd = fake
    started, thread, ctrl = accel_pppd_process.start(
        pppd, [], cmd, 5.0, env=dict(os.environ)
    )
    assert started
    with pytest.raises(AssertionError):
        accel_pppd_process.end(thread, ctrl, cmd, 5.0)


def test_cli_hang_is_bounded(fake, monkeypatch):
    monkeypatch.setenv("FAKE_HANG", "1")
    _, cmd = fake
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        process.run([cmd, "l2tp switch show"], timeout=1.0)
    assert time.monotonic() - start < 10


def test_cli_default_timeout_applies(fake, monkeypatch):
    monkeypatch.setenv("FAKE_HANG", "1")
    monkeypatch.setattr(process, "default_timeout", 1.0)
    _, cmd = fake
    with pytest.raises(subprocess.TimeoutExpired):
        process.run([cmd, "l2tp switch show"])


def test_peer_wait_kills_a_stuck_harness(tmp_path):
    sleeper = _script(tmp_path / "peer", "#!{py}\nimport time\ntime.sleep(600)\n")
    thread, ctrl = l2tp_peer_process.start(sleeper, [])
    assert thread.daemon
    rc, _, _ = l2tp_peer_process.wait(thread, ctrl, 0.5)
    assert rc is not None and rc != 0
    assert not thread.is_alive()


def test_peer_wait_can_leave_the_harness_running(tmp_path):
    sleeper = _script(tmp_path / "peer", "#!{py}\nimport time\ntime.sleep(600)\n")
    thread, ctrl = l2tp_peer_process.start(sleeper, [])
    try:
        rc, _, _ = l2tp_peer_process.wait(thread, ctrl, 0.3, kill_on_timeout=False)
        assert rc is None
    finally:
        ctrl["process"].kill()
        thread.join(5.0)


def test_startup_failure_is_not_an_exit_failure(tmp_path):
    # tests that provoke a rejected config expect the daemon to die at start
    pppd = _script(tmp_path / "pppd", "#!{py}\nimport sys\nsys.exit(1)\n")
    cmd = _script(tmp_path / "cmd", "#!{py}\nimport sys\nsys.exit(1)\n")
    started, thread, ctrl = accel_pppd_process.start(pppd, [], cmd, 5.0)
    assert not started
    accel_pppd_process.end(thread, ctrl, cmd, 5.0, check_exit=True)
    assert ctrl["returncode"] == 1


def test_killed_daemon_warns_instead_of_failing(tmp_path):
    pppd = _script(tmp_path / "pppd", "#!{py}\nimport time\ntime.sleep(600)\n")
    cmd = _script(tmp_path / "cmd", "#!{py}\n")  # replies, never stops it
    started, thread, ctrl = accel_pppd_process.start(pppd, [], cmd, 5.0)
    assert started
    with pytest.warns(UserWarning, match="was killed"):
        accel_pppd_process.end(thread, ctrl, cmd, 0.3, check_exit=True)
    assert ctrl["killed"] and ctrl["returncode"] == -9


KNOWN_NULL_CTX_ERR = (
    "/src/accel-pppd/triton/triton.c:720:2: runtime error: member access "
    "within null pointer of type 'struct _triton_context_t'\n"
    "    #0 0x1 in triton_context_call /src/accel-pppd/triton/triton.c:720\n"
    "    #1 0x2 in do_log /src/accel-pppd/log.c:106\n"
)


@pytest.mark.parametrize(
    "extra, waived",
    [
        ("", True),
        ("==1==ERROR: AddressSanitizer: heap-use-after-free\n", False),
        ("x.c:1:1: runtime error: signed integer overflow\n", False),
    ],
)
def test_known_shutdown_null_ctx_is_waived_narrowly(fake, tmp_path, extra, waived):
    pppd = _script(
        tmp_path / "pppd",
        "#!{py}\nimport os, sys, time\n"
        "while not os.path.exists(os.environ['FAKE_FLAG']):\n    time.sleep(0.02)\n"
        f"sys.stderr.write({KNOWN_NULL_CTX_ERR!r})\n"
        f"sys.stderr.write({extra!r})\nsys.exit(1)\n",
    )
    cmd = _script(tmp_path / "cmd", FAKE_CMD)
    started, thread, ctrl = accel_pppd_process.start(
        pppd, [], cmd, 5.0, env=dict(os.environ)
    )
    assert started
    if waived:
        with pytest.warns(UserWarning, match="known shutdown bug"):
            accel_pppd_process.end(thread, ctrl, cmd, 5.0, check_exit=True)
    else:
        with pytest.raises(AssertionError, match="exited with status 1"):
            accel_pppd_process.end(thread, ctrl, cmd, 5.0, check_exit=True)
