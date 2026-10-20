import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, start_instance, switch_show, wait_up


def _run(accel_cmd, accel_pppd, peer_bin, rule_value, calling, calling2):
    """Sends an ICRQ with two Calling-Number AVPs [calling, calling2] to a
    switch whose only rule matches `rule_value`. Returns (matched counter
    line present, output of the downstream harness)."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "4",
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
    match=Calling-Number,exact,{rule_value},downstream
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
                    "--calling-number", calling,
                    "--calling-number2", calling2,
                ],
            )
            rc, out, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
            assert rc == 0, err

            shown = switch_show(accel_cmd, switch_cli)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        rc, dout, derr = finish_harness(down_thread, down_ctrl, 10.0)

    return shown, dout


@pytest.mark.l2tp_switch
def test_rule_matching_only_a_later_duplicate_calling_number_does_not_match(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """Matching and forwarding use the same Calling-Number, the first: a rule
    for the second of two AVPs must not route the call."""
    shown, dout = _run(accel_cmd, accel_pppd, peer_bin, "999", "472913", "999")

    assert "matched: 0" in shown, shown
    assert "event=recv_icrq " not in dout, dout


@pytest.mark.l2tp_switch
def test_forwarded_calling_number_is_the_matched_one(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The rule matched the first Calling-Number, so that is the one the
    downstream ICRQ carries, not the later duplicate."""
    shown, dout = _run(accel_cmd, accel_pppd, peer_bin, "472913", "472913", "999")

    assert "matched: 1" in shown, shown
    assert "event=recv_icrq_calling round=0 value=472913" in dout, dout
