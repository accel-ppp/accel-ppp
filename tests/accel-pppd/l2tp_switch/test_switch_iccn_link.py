import re

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, read_log, start_instance, wait_for, wait_up

TX_SPEED = 56000
FRAMING = 1
RX_SPEED = 128000
GROUP = "customer-vpn-7"


def _downstream_iccn(accel_pppd, accel_cmd, peer_bin, call_args):
    """Runs one call through a switch and returns the ICCN line the
    downstream peer reported."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

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

            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    *call_args,
                    # A harness that exits at once leaves the switch's next
                    # packet to its closed port; the ICMP error ends the
                    # upstream tunnel, and the call with it, before the ICCN
                    # is forwarded. Hold the socket until that happened.
                    "--hold-seconds", "3",
                ],
            )
            assert wait_for(
                lambda: "sending ICCN" in read_log(s_cfg), 10.0
            ), "the switch never forwarded the ICCN downstream"
            rc, _, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
            assert rc == 0, err
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, out, err = finish_harness(down_thread, down_ctrl, 15.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{err}"

    m = re.search(
        r"event=recv_iccn_link round=\d+ tx=(\d+) framing=(\d+) rx=(\d+) group=(\S*)",
        out,
    )
    assert m, out
    return m


@pytest.mark.l2tp_switch
def test_downstream_iccn_carries_upstream_speed_and_framing(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """The downstream LNS has to see the line speed and framing the upstream
    LAC reported, not values the switch made up."""
    m = _downstream_iccn(
        accel_pppd, accel_cmd, peer_bin,
        ["--tx-speed", str(TX_SPEED), "--framing", str(FRAMING)],
    )

    assert (int(m.group(1)), int(m.group(2))) == (TX_SPEED, FRAMING), m.group(0)


@pytest.mark.l2tp_switch
def test_downstream_iccn_carries_the_optional_avps(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """RX speed and the private group id are repeated downstream, which
    would otherwise bill a call at the wrong rate and put it in no group."""
    m = _downstream_iccn(
        accel_pppd, accel_cmd, peer_bin,
        ["--rx-speed", str(RX_SPEED), "--private-group-id", GROUP],
    )

    assert int(m.group(3)) == RX_SPEED, m.group(0)
    assert m.group(4) == GROUP, m.group(0)
