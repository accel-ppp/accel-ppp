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


def _start_call(peer_bin, switch_l2tp, extra=()):
    return l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(switch_l2tp),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
            *extra,
        ],
    )


@pytest.mark.l2tp_switch
def test_switched_calls_count_against_max_sessions(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """A switched call has no ap_session but holds two sockets, four pipes and
    large socket buffers, so max-sessions has to cover it."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
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
    [common]
    max-sessions=1
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = _start_call(peer_bin, switch_l2tp)
            rc, _, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
            assert rc == 0, err

            out = ""

            def one_active():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active=1" in out

            assert wait_for(one_active, 5.0), out

            # The limit is reached: this ICRQ is discarded, so the peer gets
            # no ICRP and is killed by the timeout.
            thread, ctrl = _start_call(peer_bin, switch_l2tp)
            finish_harness(thread, ctrl, 4.0)

            out = switch_show(accel_cmd, switch_cli)
            assert "matched: 1" in out, out + read_log(s_cfg)
            assert "active=1" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
