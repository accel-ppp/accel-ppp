"""on-demand targets: the idle linger that closes a tunnel after its last call.

The tunnel stays up for idle-linger after the last call ends, and a call
arriving inside that window reuses it and restarts the window from its own end.
The tests check when things happen on the downstream peer's side.

The downstream is the peer harness in --listen --hold-seconds mode because a
real accel-ppp downstream closes its tunnel a few hundred milliseconds after
the call ends, before the switch's linger could be observed.
"""

import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports, start_instance, switch_show,
    wait_for, wait_for_tunnels_active,
)

# Must match idle-linger= in the [l2tp-switch] configs below.
IDLE_LINGER = 8.0

# Written through the established call before it is torn down. The harness
# pauses around it, which lets the switch finish pairing the call downstream.
DATA_PATTERN = "SWITCHOK"


def _wait_show(accel_cmd, cli_port, needle, timeout):
    """Poll `l2tp switch show` until `needle` appears; return (found, out)."""
    out = [""]

    def seen():
        out[0] = switch_show(accel_cmd, cli_port)
        return needle in out[0]

    return bool(wait_for(seen, timeout)), out[0]


def _events(out):
    """Return [(event-name, timestamp), ...] in the order the harness logged them."""
    return [
        (m.group(1), float(m.group(2)))
        for m in re.finditer(r"event=(\S+) round=\d+ t=([\d.]+)", out)
    ]


def _stopccn_result(out):
    m = re.search(r"event=recv_stopccn round=\d+ t=[\d.]+ res=(\d+)", out)
    return int(m.group(1)) if m else None


def _times(events, name):
    return [t for (event, t) in events if event == name]


def _start_downstream(peer_bin, port, hold):
    return l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(port),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", str(hold),
        ],
    )


def _place_and_end_one_call(peer_bin, accel_cmd, cli_port, peer_port, expect_connected):
    """Run one switched call to completion and end it from the upstream side.

    Return the time the switch is first seen with no active call, which is when
    its idle linger starts. --send-stopccn ends the call; a harness exit alone
    would leave the upstream tunnel to its own timeouts.
    """
    thread, ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(peer_port),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
            "--data-pattern", DATA_PATTERN,
            "--send-stopccn",
        ],
    )
    rc, out, err = l2tp_peer_process.wait(thread, ctrl, 30.0)
    assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{out}"

    idle, show = _wait_show(accel_cmd, cli_port, "active: 0", 15.0)
    ended = time.monotonic()
    assert idle, f"call never ended:\n{show}"
    assert f"connected: {expect_connected}" in show, (
        "the call was never actually paired downstream, so nothing was ever"
        f" active to go idle:\n{show}"
    )
    # "[idle]" means no active calls; it does not show the tunnel is still
    # open. A missing linger is caught by the downstream-side timing assertions
    # (CDN to StopCCN delta).
    assert "[idle]" in show, (
        f"target's tunnel is not idle immediately after its last call"
        f" ended:\n{show}"
    )
    return ended


def _start_switch(accel_pppd, accel_cmd, cli_port, l2tp_port, downstream_port):
    return start_instance(
        accel_pppd,
        accel_cmd,
        cli_port,
        "127.0.0.1",
        l2tp_port,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{downstream_port},downstreamsecret,on-demand
    idle-linger={int(IDLE_LINGER)}
    match=Calling-Number,exact,472913,downstream
    """,
    )


@pytest.mark.l2tp_switch
def test_on_demand_tunnel_closes_after_idle_linger(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    down_thread, down_ctrl = _start_downstream(peer_bin, down_l2tp, 45)

    try:
        s_started, s_thread, s_ctrl, s_cfg = _start_switch(
            accel_pppd, accel_cmd, switch_cli, switch_l2tp, down_l2tp
        )
        assert s_started

        try:
            out = switch_show(accel_cmd, switch_cli)
            assert "[idle]" in out, f"on-demand target connected with no call:\n{out}"

            ended = _place_and_end_one_call(peer_bin, accel_cmd, switch_cli, switch_l2tp, 1)

            # Wait for the tunnel to close on its own. Its open time is asserted from
            # the downstream peer's timestamps, since a client-side timestamp lags the
            # daemon by seconds on a slow runner.
            closed, _, n = wait_for_tunnels_active(accel_cmd, 0, IDLE_LINGER + 20.0, switch_cli)
            assert closed, (
                "target's tunnel never closed on its own; it is waiting for"
                " the downstream peer's own idle policy instead of closing"
                f" itself (tunnels active={n})"
            )
            out = switch_show(accel_cmd, switch_cli)
            assert "[idle]" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = l2tp_peer_process.wait(down_thread, down_ctrl, 60.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

    # The same check from the downstream peer's side of the wire.
    events = _events(down_out)
    cdn = _times(events, "recv_cdn")
    stopccn = _times(events, "recv_stopccn")
    assert len(_times(events, "recv_sccrq")) == 1, f"expected one tunnel:\n{down_out}"
    assert len(_times(events, "recv_icrq")) == 1, f"expected one call:\n{down_out}"
    assert cdn and stopccn, (
        f"downstream never saw the call end and the tunnel close:\n{down_out}"
    )
    linger = stopccn[0] - cdn[0]
    assert IDLE_LINGER * 0.8 < linger < IDLE_LINGER + 5.0, (
        f"switch closed the tunnel {linger:.1f}s after disconnecting the"
        f" call, not the {IDLE_LINGER:.0f}s linger:\n{down_out}"
    )
    # Result 1 (general request to clear the control connection): an
    # administrative close a peer can tell apart from an error.
    assert _stopccn_result(down_out) == 1, (
        f"idle teardown's StopCCN did not carry result code 1:\n{down_out}"
    )


@pytest.mark.l2tp_switch
def test_on_demand_linger_cancelled_by_a_new_call(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    # The second call is placed half a linger after the first ended: inside
    # its window, and late enough that the first linger's deadline falls after
    # the second call is over. A teardown that fires blindly would close the
    # tunnel before the second call gets a full window.
    gap = IDLE_LINGER * 0.25

    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    down_thread, down_ctrl = _start_downstream(peer_bin, down_l2tp, 90)

    try:
        s_started, s_thread, s_ctrl, s_cfg = _start_switch(
            accel_pppd, accel_cmd, switch_cli, switch_l2tp, down_l2tp
        )
        assert s_started

        try:
            _place_and_end_one_call(peer_bin, accel_cmd, switch_cli, switch_l2tp, 1)
            time.sleep(gap)
            _place_and_end_one_call(peer_bin, accel_cmd, switch_cli, switch_l2tp, 2)

            # Reuse of the first tunnel and the full second window are asserted
            # below from the downstream peer's timestamps.
            closed, _, n = wait_for_tunnels_active(accel_cmd, 0, IDLE_LINGER + 20.0, switch_cli)
            assert closed, f"tunnel never closed on its own (tunnels active={n})"
            out = switch_show(accel_cmd, switch_cli)
            assert "[idle]" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = l2tp_peer_process.wait(down_thread, down_ctrl, 60.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

    events = _events(down_out)
    # Two calls, one tunnel: a second SCCRQ would mean a reconnect.
    assert len(_times(events, "recv_sccrq")) == 1, (
        f"the second call did not reuse the first call's tunnel:\n{down_out}"
    )
    assert len(_times(events, "recv_icrq")) == 2, (
        f"expected both calls to be placed on that one tunnel:\n{down_out}"
    )

    cdn = _times(events, "recv_cdn")
    stopccn = _times(events, "recv_stopccn")
    assert len(cdn) == 2 and stopccn, (
        f"downstream never saw both calls end and the tunnel close:\n{down_out}"
    )
    # Measured from the second call's end; the first call's deadline is 5s
    # earlier and nothing happened there.
    linger = stopccn[0] - cdn[1]
    assert IDLE_LINGER * 0.8 < linger < IDLE_LINGER + 5.0, (
        f"switch closed the tunnel {linger:.1f}s after the second call ended"
        f" ({stopccn[0] - cdn[0]:.1f}s after the first); the second call did"
        f" not get its own {IDLE_LINGER:.0f}s window:\n{down_out}"
    )
