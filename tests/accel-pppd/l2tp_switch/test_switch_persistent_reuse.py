import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports,
    finish_harness,
    read_log,
    start_instance,
    switch_show,
    wait_for,
    wait_up,
)


def _place_call(peer_bin, switch_l2tp):
    thread, ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(switch_l2tp),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
            "--wait-cdn",
        ],
    )
    return l2tp_peer_process.wait(thread, ctrl, 10.0)


@pytest.mark.l2tp_switch
def test_persistent_target_stays_up_after_last_call(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """The docs promise a persistent tunnel is kept up whether or not a call
    uses it: it must survive its last call and carry the next one.

    The downstream is the peer harness, not an accel LNS: accel's own LNS
    sends a StopCCN when its last session ends, which would hide a StopCCN
    sent by the switch itself.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    # One round: a second SCCRQ would go unanswered, so the test fails if the
    # switch reconnects instead of reusing its tunnel.
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--cdn-after-iccn-ms", "300",
            "--hold-seconds", "30",
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

            rc, _, err = _place_call(peer_bin, switch_l2tp)
            assert rc == 0, err

            out = ""

            def call_gone():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active=0" in out

            assert wait_for(call_gone, 5.0), out

            # The last call ending must not close the tunnel. A StopCCN takes
            # the target to [down], so watch for that before the next call.
            assert not wait_for(
                lambda: "[down]" in switch_show(accel_cmd, switch_cli), 3.0, scale=False
            ), switch_show(accel_cmd, switch_cli) + read_log(s_cfg)

            rc, _, err = _place_call(peer_bin, switch_l2tp)
            assert rc == 0, err
            out = switch_show(accel_cmd, switch_cli)
            assert "matched: 2" in out, out
            assert "connected: 2" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
