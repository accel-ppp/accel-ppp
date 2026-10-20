import os

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, start_instance, wait_up

CALLS = int(os.environ.get("L2TP_STATE_RACE_CALLS", "40"))
PARALLEL = 4


def _start_call(peer_bin, switch_l2tp):
    return l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(switch_l2tp),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
            "--send-stopccn",
        ],
    )


@pytest.mark.l2tp_switch
def test_state_is_race_free_across_tunnel_contexts(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """Many short calls, each ICCN immediately followed by a StopCCN, against
    one persistent target. The upstream tunnel is torn down on its own context
    (reading the downstream leg's state) while the target tunnel's context
    places the downstream call (writing it). Functionally this always passes;
    it exists for the TSAN leg, which reports a plain int shared this way.
    L2TP_STATE_RACE_CALLS raises the call count for a longer soak."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "600",
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
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started
        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)
            done = 0
            while done < CALLS:
                batch = [
                    _start_call(peer_bin, switch_l2tp)
                    for _ in range(min(PARALLEL, CALLS - done))
                ]
                for thread, ctrl in batch:
                    finish_harness(thread, ctrl, 30.0)
                done += len(batch)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 15.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 8.0)
