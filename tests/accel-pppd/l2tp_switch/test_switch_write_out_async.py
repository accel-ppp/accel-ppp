import os
import subprocess
import time
from pathlib import Path

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, switch_show, wait_up, wait_for, read_log, finish_harness

DATA_PATTERN = "SWITCHOK"
# Well under L2TP_SWITCH_EAGAIN_MAX_WAITS * L2TP_SWITCH_EAGAIN_POLL_MS (~5s):
# long enough to make a stall obvious, short enough that the call survives.
EAGAIN_WINDOW_MS = 2500
# Upper bound for a responsive daemon to answer a CLI query: generous for a
# loaded runner but far below EAGAIN_WINDOW_MS, so it separates a blocked
# daemon from a working one.
CLI_RESPONSIVE_S = 1.0

_SHIM_SRC = Path(__file__).resolve().parent / "splice_eagain_shim.c"


@pytest.fixture(scope="module")
def splice_eagain_shim(tmp_path_factory):
    out = tmp_path_factory.mktemp("splice_eagain_shim") / "splice_eagain_shim.so"
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


@pytest.mark.l2tp_switch
def test_switch_backpressure_does_not_stall_the_tunnels_cli(
    accel_cmd, accel_pppd, peer_bin, splice_eagain_shim, tmp_path
):
    """A backpressured call must not stall the tunnel's CLI.

    l2tp_switch_link_write_out() waits with poll() on EAGAIN, and with
    thread-count=1 that blocks everything on the daemon. An LD_PRELOAD shim makes
    splice() return EAGAIN for this call's marked payload for EAGAIN_WINDOW_MS,
    then lets it through.
    """
    switch_cli, down_cli, switch_l2tp, down_l2tp = alloc_ports(4)
    shim_log = str(tmp_path / "shim.log")
    # An ASAN-built daemon refuses to start when a preloaded shim precedes
    # libasan; the shim only wraps splice(), so skipping that check is safe.
    asan_options = ":".join(
        filter(None, [os.environ.get("ASAN_OPTIONS"), "verify_asan_link_order=0"])
    )
    env = dict(
        os.environ,
        ASAN_OPTIONS=asan_options,
        LD_PRELOAD=str(splice_eagain_shim),
        SPLICE_EAGAIN_SHIM_MARKER=DATA_PATTERN,
        SPLICE_EAGAIN_SHIM_MS=str(EAGAIN_WINDOW_MS),
        SPLICE_EAGAIN_SHIM_LOG=shim_log,
    )

    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, down_cli, "127.0.0.1", down_l2tp, "downstreamsecret"
    )
    assert d_started

    peer_thread = peer_ctrl = None
    try:
        # thread_count=1 puts every context on one worker thread, as on a 1-vCPU
        # box. On multiple threads the CLI could run elsewhere and the test would
        # pass without the fix.
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
            thread_count=1,
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
                lambda: any(l.startswith("eagain-begin") for l in _shim_log_lines(shim_log)),
                10.0,
            ), (
                "the shim never saw the marked payload; nothing was"
                " exercised"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            # The forced-EAGAIN window is open. Query the daemon over its CLI and time
            # the round trip.
            start = time.monotonic()
            out = switch_show(accel_cmd, switch_cli)
            elapsed = time.monotonic() - start

            assert "[up]" in out
            assert elapsed < CLI_RESPONSIVE_S, (
                f"'l2tp switch show' took {elapsed:.2f}s while a single"
                " switched call's downstream leg was backpressured; the"
                " tunnel's own context (CLI included) was stalled waiting"
                " on l2tp_switch_link_write_out(), which the"
                " blocking retry there must not do"
                f"\n--- shim log ---\n" + "\n".join(_shim_log_lines(shim_log))
                + f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            # The call itself must still be alive.
            assert wait_for(
                lambda: any(l.startswith("eagain-end") for l in _shim_log_lines(shim_log)),
                10.0,
            ), "the forced-EAGAIN window never closed; the call likely died"

            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, err
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        if peer_thread:
            finish_harness(peer_thread, peer_ctrl, 15.0)
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
