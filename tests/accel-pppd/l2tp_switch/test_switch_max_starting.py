import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports,
    finish_harness,
    read_log,
    start_instance,
    switch_show,
    wait_for,
)


def _start_call(peer_bin, switch_l2tp):
    return l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(switch_l2tp),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
            "--hold-seconds", "10",
        ],
    )


@pytest.mark.l2tp_switch
def test_switched_calls_count_against_max_starting(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """A switched call has no ap_session, so it is never "starting" for the
    core. While its downstream tunnel is still being set up it still has to
    count towards max-starting."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--sccrp-delay-ms", "6000",
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
    max-starting=1
    [l2tp-switch]
    target=slow,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,slow
    """,
        )
        assert s_started

        try:
            # Matched, but the downstream SCCRP is still 6 s away: starting.
            first_thread, first_ctrl = _start_call(peer_bin, switch_l2tp)
            try:
                def matched():
                    return "matched: 1" in switch_show(accel_cmd, switch_cli)

                assert wait_for(matched, 5.0), read_log(s_cfg)

                # The limit is reached: this call is discarded unmatched.
                thread, ctrl = _start_call(peer_bin, switch_l2tp)
                finish_harness(thread, ctrl, 4.0)

                out = switch_show(accel_cmd, switch_cli)
                assert "matched: 1" in out, out + read_log(s_cfg)
            finally:
                finish_harness(first_thread, first_ctrl, 12.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
