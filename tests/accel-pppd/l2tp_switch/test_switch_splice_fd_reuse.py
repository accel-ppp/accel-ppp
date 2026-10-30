import os
import socket
import subprocess
import time
from pathlib import Path

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, wait_up, wait_for, read_log, finish_harness

DATA_PATTERN = "SWITCHOK"
SHIM_DELAY_MS = 3000
# Connections held open on the daemon CLI port at once. accept() hands out
# the lowest free fds, so the destination leg's just-closed number is among
# the first few.
CLI_CONNECTIONS = 64

_SHIM_SRC = Path(__file__).resolve().parent / "splice_delay_shim.c"


@pytest.fixture(scope="module")
def splice_delay_shim(tmp_path_factory):
    out = tmp_path_factory.mktemp("splice_delay_shim") / "splice_delay_shim.so"
    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O1", "-Wall", "-o", str(out), str(_SHIM_SRC), "-ldl"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return str(out)


def _shim_log_lines(path):
    try:
        return Path(path).read_text().splitlines()
    except OSError:
        return []


def _drain(conns):
    """Return the bytes currently readable on each connection, joined."""
    data = b""
    for conn in conns:
        while True:
            try:
                chunk = conn.recv(4096)
            except (BlockingIOError, ConnectionError):
                break
            if not chunk:
                break
            data += chunk
    return data


@pytest.mark.l2tp_switch
def test_switch_never_splices_into_a_reused_destination_fd(
    accel_cmd, accel_pppd, peer_bin, splice_delay_shim, tmp_path
):
    """The upstream->downstream splice must not write into a reused fd.

    The downstream tunnel's context can close its socket (call teardown) while
    the upstream context is about to splice into it, and the fd number may be
    handed to an unrelated open() such as a new CLI connection. The shim delays
    the upstream leg's splice of the marked payload by SHIM_DELAY_MS so the
    window is wide enough: the downstream ends the call in that time and the
    test opens fresh CLI connections. The payload must not show up on any.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    shim_log = str(tmp_path / "shim.log")
    # An ASAN-built daemon refuses to start when the preloaded shim precedes
    # libasan; the shim only wraps splice(), so skipping that check is safe.
    asan_options = ":".join(
        filter(None, [os.environ.get("ASAN_OPTIONS"), "verify_asan_link_order=0"])
    )
    env = dict(
        os.environ,
        ASAN_OPTIONS=asan_options,
        LD_PRELOAD=splice_delay_shim,
        SPLICE_SHIM_MARKER=DATA_PATTERN,
        SPLICE_SHIM_DELAY_MS=str(SHIM_DELAY_MS),
        SPLICE_SHIM_LOG=shim_log,
    )

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "12",
            # The downstream target ends the call while the shim still holds up the
            # splice (the upstream harness writes it 300ms after its ICCN).
            "--cdn-after-iccn-ms", "700",
        ],
    )
    conns = []
    peer_thread = peer_ctrl = None

    try:
        # thread-count 4: the two legs' tunnel contexts must be able to run on
        # different worker threads.
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            switch_cli,
            "127.0.0.1",
            switch_l2tp,
            "upstreamsecret",
            extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
            thread_count=4,
            env=env,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                    "--hold-seconds", "6",
                ],
            )

            assert wait_for(
                lambda: any(l.startswith("delay-begin") for l in _shim_log_lines(shim_log)),
                10.0,
            ), (
                "the upstream payload never reached the switch's splice --"
                " nothing was exercised"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            # Let the target's CDN land and the downstream leg close its socket, then
            # take fd numbers off the daemon.
            time.sleep(1.5)
            for _ in range(CLI_CONNECTIONS):
                conn = socket.create_connection(("127.0.0.1", switch_cli), timeout=5.0)
                conn.setblocking(False)
                conns.append(conn)
                # Paced: the CLI listen backlog is tiny and an overflowing connect() stalls
                # for a SYN retransmit.
                time.sleep(0.01)

            assert wait_for(
                lambda: any(l.startswith("delay-end") for l in _shim_log_lines(shim_log)),
                10.0,
            ), "the delayed splice never resumed"
            time.sleep(0.5)  # the splice has run by now; let its bytes arrive

            leaked = _drain(conns)
            assert DATA_PATTERN.encode() not in leaked, (
                "the upstream leg's PPP payload was spliced into an unrelated"
                " fd: the downstream leg's socket was closed and its fd"
                " number reused while the upstream leg still held it"
                f"\n--- shim log ---\n" + "\n".join(_shim_log_lines(shim_log))
                + f"\n--- switch log ---\n{read_log(s_cfg)}"
            )
        finally:
            for conn in conns:
                conn.close()
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        if peer_thread:
            finish_harness(peer_thread, peer_ctrl, 15.0)
        finish_harness(down_thread, down_ctrl, 15.0)
