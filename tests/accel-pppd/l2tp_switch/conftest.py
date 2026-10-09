import subprocess
from pathlib import Path

import pytest

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
    log_syslog
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
