import subprocess
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, read_log, finish_harness

DATA_PATTERN = "SWITCHOK"


@pytest.mark.l2tp_switch
def test_switch_upstream_data_sent_during_slow_downstream_connect_is_not_lost(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """Data the upstream peer sends during a slow downstream connect is not lost.

    The upstream leg's pppol2tp socket is connected only after the downstream
    handshake finishes (l2tp_switch_finish_upstream()). Until then the kernel has
    no session for it and drops any data frame the upstream peer sends. The
    harness's 300ms pre-write sleep covers near-instant targets, but a cold
    on-demand target can take over a second to answer.
    """
    sccrp_delay = 1.5
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "10",
            "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
        ],
    )

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
    target=slow,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,slow
    """,
        )
        assert s_started

        try:
            capture = subprocess.Popen(
                ["tcpdump", "-l", "-A", "-i", "lo", "udp", "port", str(down_l2tp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(0.5)  # let tcpdump attach before traffic starts

            try:
                # The harness default hold outlasts sccrp_delay. The call must not hang up
                # before the slow downstream leg connects, or the queued call is torn down.
                peer_thread, peer_ctrl = l2tp_peer_process.start(
                    peer_bin,
                    [
                        "--peer-addr", "127.0.0.1",
                        "--peer-port", str(switch_l2tp),
                        "--secret", "upstreamsecret",
                        "--calling-number", "472913",
                        "--data-pattern", DATA_PATTERN,
                        "--hold-seconds", str(sccrp_delay + 2.5),
                    ],
                )
                rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
                assert rc == 0, (
                    f"upstream harness failed (rc={rc}): {err}\n{out}"
                    f"\n--- switch log ---\n{read_log(s_cfg)}"
                )

                # Let the downstream handshake finish and the buffered write be spliced.
                time.sleep(sccrp_delay + 1.0)
            finally:
                capture.terminate()
                capture_out, _ = capture.communicate(timeout=5.0)

            assert DATA_PATTERN in capture_out, (
                "the upstream peer's data, written right after its own"
                " ICCN while the downstream leg was still mid-handshake,"
                " never reached the downstream target; it was dropped"
                " by the kernel because the upstream session's own socket"
                " was not connected yet"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 15.0)
