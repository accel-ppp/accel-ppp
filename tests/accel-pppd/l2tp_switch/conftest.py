import os
import socket
import subprocess
from pathlib import Path

import pytest
from common import accel_pppd_process, process

# l2tp_switch_peer_test.c is not part of the cmake build (it stubs the AVP
# dictionary and links packet.c standalone), so the session fixture below
# builds it.
_PEER_TEST_SRC_DIR = Path(__file__).resolve().parents[3] / "accel-pppd" / "ctrl" / "l2tp"


def _build_peer_test(sanitize, out_path):
    cmd = [
        "gcc",
        "-O1",
        "-g",
        "-Wall",
        "-fno-strict-aliasing",
        "-D_GNU_SOURCE",
        "-pthread",
    ]
    if sanitize:
        cmd += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    cmd += [
        "-I",
        str(_PEER_TEST_SRC_DIR / ".." / ".." / "include"),
        "-I",
        str(_PEER_TEST_SRC_DIR),
        "-o",
        str(out_path),
        *sorted(str(p) for p in _PEER_TEST_SRC_DIR.glob("l2tp_switch_peer_*.c")),
        str(_PEER_TEST_SRC_DIR / "packet.c"),
        "-lcrypto",
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


# switching hands PPP frames between two PPPoL2TP sockets, which need the
# l2tp_ppp kernel module; the numbers are not exported by python's socket module
_AF_PPPOX = 24
_PX_PROTO_OL2TP = 1


# CI sets this where it loads l2tp_ppp, so a missing module fails the run
# instead of silently skipping the tests that need it.
_REQUIRE_PPPOL2TP_ENV = "L2TP_SWITCH_REQUIRE_PPPOL2TP"

# test modules that never connect a call, so never open a PPPoL2TP socket
_NO_PPPOL2TP_MODULES = frozenset(
    {"test_switch_config", "test_switch_cli", "test_switch_tunnel"}
)


@pytest.fixture(scope="session")
def _pppol2tp_error():
    """None when PPPoL2TP sockets can be created, else the OSError text."""
    try:
        socket.socket(_AF_PPPOX, socket.SOCK_DGRAM, _PX_PROTO_OL2TP).close()
    except OSError as e:
        return str(e)
    return None


@pytest.fixture(autouse=True)
def l2tp_ppp_available(request, _pppol2tp_error):
    """Skips the tests that open PPPoL2TP sockets when the kernel has none,
    or fails them when L2TP_SWITCH_REQUIRE_PPPOL2TP=1."""
    if request.module.__name__.rsplit(".", 1)[-1] in _NO_PPPOL2TP_MODULES:
        return
    if _pppol2tp_error is None:
        return
    msg = f"PPPoL2TP sockets are not available (l2tp_ppp module?): {_pppol2tp_error}"
    if os.environ.get(_REQUIRE_PPPOL2TP_ENV) == "1":
        pytest.fail(f"{msg}; {_REQUIRE_PPPOL2TP_ENV}=1 requires them", pytrace=False)
    pytest.skip(msg)


@pytest.fixture(scope="session", autouse=True)
def l2tp_switch_peer_test_binary(tmp_path_factory):
    # Prefer a sanitized build, but fall back to a plain one on hosts without
    # the libasan/libubsan runtime (e.g. Alpine/musl).
    # The binary goes in a per-session temp dir so xdist workers do not
    # rebuild it under each other.
    out_path = tmp_path_factory.mktemp("l2tp_switch_peer") / "l2tp_switch_peer_test"
    result = _build_peer_test(sanitize=True, out_path=out_path)
    if result.returncode != 0:
        sanitized_error = result.stdout + result.stderr
        result = _build_peer_test(sanitize=False, out_path=out_path)
        if result.returncode != 0:
            pytest.fail(
                "failed to build l2tp_switch_peer_test (needed by every "
                "l2tp_switch test), both with and without "
                "-fsanitize=address,undefined:\n--- sanitized ---\n"
                + sanitized_error
                + "\n--- plain ---\n"
                + result.stdout
                + result.stderr
            )
    return str(out_path)


@pytest.fixture(scope="session")
def peer_bin(l2tp_switch_peer_test_binary):
    """Path of the built l2tp_switch_peer_test harness binary."""
    return l2tp_switch_peer_test_binary


# Upper bound for every accel-cmd (or other process.run) call in these tests;
# accel-cmd without -t would wait forever on a hung daemon.
CLI_TIMEOUT = 30.0


@pytest.fixture(autouse=True)
def bounded_cli_calls(monkeypatch):
    monkeypatch.setattr(process, "default_timeout", CLI_TIMEOUT)


@pytest.fixture(autouse=True)
def accel_pppd_exit_checked(monkeypatch):
    """Makes accel_pppd_process.end() fail the test on a non-zero or signal
    exit of the daemon (sanitizer reports at exit land there). Only affects the l2tp_switch tests; the other
    suites keep the historic behaviour."""
    real_end = accel_pppd_process.end

    def strict_end(*args, **kwargs):
        kwargs.setdefault("check_exit", True)
        return real_end(*args, **kwargs)

    monkeypatch.setattr(accel_pppd_process, "end", strict_end)


@pytest.fixture(autouse=True)
def accel_pppd_crash_visible(monkeypatch):
    """Starts every daemon with --no-sigsegv.

    By default a SIGSEGV runs the daemon's handler, which closes all
    descriptors and re-executes it under the same pid. Another thread then
    fails on its closed epoll/log descriptors, e.g. triton_md_enable_handler()
    -> abort() with its BUG message written to a closed log-error fd: a
    SIGABRT with empty stderr far from the real crash, or a daemon that
    looks hung because it restarted. Without the handler the crash is a
    plain SIGSEGV (or a sanitizer report) at the real site. Also lets
    the daemon write a core file."""
    real_start = accel_pppd_process.start

    def crash_visible_start(accel_pppd, args, *rest, **kwargs):
        if "--no-sigsegv" not in args:
            args = ["--no-sigsegv"] + list(args)
        return real_start(accel_pppd, args, *rest, **kwargs)

    monkeypatch.setattr(accel_pppd_process, "start", crash_visible_start)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "xdist_group(name): tests sharing a name run on one xdist worker"
        " (used for tests that need the fixed-port shared daemon fixture)",
    )


@pytest.fixture()
def l2tp_switch_config():
    # overridden by individual tests
    return ""


@pytest.fixture()
def accel_pppd_config(l2tp_switch_config):
    return (
        """
    [modules]
    log_file
    l2tp

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [l2tp]
    verbose=1
    secret=testsecret

    """
        + l2tp_switch_config
    )
