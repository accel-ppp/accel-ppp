import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
from common import config, accel_pppd_process, l2tp_peer_process, process
from helpers import (
    alloc_ports,
    EXIT_WAIT,
    finish_harness,
    start_instance,
    switch_show,
    wait_exit,
    wait_for,
    wait_up,
)

CDN_DELAY_MS = 2000

_SHIM_SRC = Path(__file__).resolve().parent / "cdn_delay_shim.c"


@pytest.fixture(scope="module")
def cdn_delay_shim(tmp_path_factory):
    out = tmp_path_factory.mktemp("cdn_delay_shim") / "cdn_delay_shim.so"
    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O1", "-Wall", "-o", str(out), str(_SHIM_SRC), "-ldl"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return str(out)


@pytest.mark.l2tp_switch
def test_shutdown_waits_for_queued_downstream_teardown(
    accel_cmd, accel_pppd, peer_bin, cdn_delay_shim
):
    """The upstream leg's teardown queues a hop on the downstream tunnel's
    context and drops the call from the shutdown bookkeeping. The shutdown
    must not complete until that hop has run: it still sends the CDN and logs,
    and the daemon must not be torn down under it.

    The shim holds the downstream CDN back by CDN_DELAY_MS. Meanwhile the
    daemon must keep serving its CLI (triton_terminate() has not started) and
    must exit cleanly once the CDN is out. Before the fix the shutdown
    completed with the hop queued and the CLI was already gone."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    asan_options = ":".join(
        filter(None, [os.environ.get("ASAN_OPTIONS"), "verify_asan_link_order=0"])
    )
    env = dict(
        os.environ,
        ASAN_OPTIONS=asan_options,
        LD_PRELOAD=cdn_delay_shim,
        CDN_SHIM_PORT=str(down_l2tp),
        CDN_SHIM_DELAY_MS=str(CDN_DELAY_MS),
    )

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "6",
        ],
    )
    peer_thread = peer_ctrl = None

    try:
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
                    "--wait-cdn",
                ],
            )
            assert wait_for(lambda: "active=1" in switch_show(accel_cmd, switch_cli), 5.0)

            started = time.monotonic()
            s_ctrl["process"].send_signal(signal.SIGTERM)

            # the shim holds the hop for CDN_DELAY_MS; part-way through, the
            # daemon is still shutting down and must still answer its CLI
            time.sleep(CDN_DELAY_MS / 2000.0)
            show = process.run([accel_cmd, "-p", str(switch_cli), "show version"])
            cli_alive = s_ctrl["process"].poll() is None and show[0] == 0

            wait_exit(s_ctrl, EXIT_WAIT, accel_cmd, switch_cli)
            elapsed = time.monotonic() - started
            rc = s_ctrl["process"].poll()

            assert cli_alive, (
                "the daemon stopped serving while a downstream teardown"
                " was still queued"
            )
            assert rc == 0, f"daemon exit status {rc} after {elapsed:.2f}s"
            assert elapsed >= CDN_DELAY_MS / 1000.0 * 0.9, (
                f"daemon exited after {elapsed:.2f}s, before the queued"
                " downstream teardown could have finished"
            )

            _, down_out, _ = finish_harness(down_thread, down_ctrl, 15.0)
            assert "event=recv_cdn" in down_out, down_out
        finally:
            if peer_thread:
                finish_harness(peer_thread, peer_ctrl, 5.0)
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
