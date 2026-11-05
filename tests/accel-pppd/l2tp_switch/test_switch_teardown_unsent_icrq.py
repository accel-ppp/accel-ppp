import re

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import WAIT_FACTOR, alloc_ports, finish_harness, start_instance, wait_up

CALLS = 8
# The listener's SCCRP carries no Recv-Window-Size: the switch assumes 4.
PEER_WINDOW = 4
SERVE_DELAY_MS = 3000


# How the upstream leg of every call ends while the downstream ICRQs wait:
# its tunnel's StopCCN or its own CDN. Both drop the downstream leg through the
# same cancel and neither may let the unsent ICRQ out first. (A shutdown ends
# the upstream legs too, but the daemon exits with the ICRQs still in its
# memory, so nothing can tell whether they would have been sent.)
HANGUPS = {
    "stopccn": ["--send-stopccn", "--stopccn-delay-ms", "1000"],
    "cdn": ["--send-cdn", "3:0", "--send-cdn-delay-ms", "1000"],
}


@pytest.mark.l2tp_switch
@pytest.mark.parametrize("hangup", list(HANGUPS))
def test_hung_up_call_does_not_place_its_unsent_icrq(pytestconfig, accel_cmd, accel_pppd, peer_bin, hangup):
    """A switched call is exempt from the send-window check, so its ICRQ can
    still be queued behind a full window when the upstream hangs up. The
    downstream must not receive that ICRQ afterwards: nothing would end the
    call it creates, and it would count against the LNS's session limits."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    # The listener does not serve its tunnel for a while, so the window stays
    # full of unacknowledged ICRQs while the upstreams hang up.
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--serve-delay-ms", str(SERVE_DELAY_MS),
            "--hold-seconds", "8",
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

            calls = [
                l2tp_peer_process.start(
                    peer_bin,
                    [
                        "--peer-addr", "127.0.0.1",
                        "--peer-port", str(switch_l2tp),
                        "--secret", "upstreamsecret",
                        "--calling-number", "472913",
                    ] + HANGUPS[hangup],
                )
                for _ in range(CALLS)
            ]
            for thread, ctrl in calls:
                rc, out, err = l2tp_peer_process.wait(thread, ctrl, 20.0 * WAIT_FACTOR)
                assert rc == 0, err

            rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 30.0 * WAIT_FACTOR)
            assert rc == 0, down_err
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    except BaseException:
        finish_harness(down_thread, down_ctrl, 5.0)
        raise

    # Retransmissions repeat a session ID; count calls, not messages.
    placed = set(re.findall(r"event=recv_icrq round=\d+ t=[\d.]+ sid=(\d+)", down_out))
    assert placed, f"no call reached the downstream at all:\n{down_out}"
    assert len(placed) <= PEER_WINDOW, (
        f"{len(placed)} of {CALLS} calls were placed on the downstream although its"
        f" window holds {PEER_WINDOW} and every upstream hung up before it was"
        f" served:\n{down_out}"
    )
