"""on-demand targets: lazy connect, call queueing, bounded connect timeout.

Nothing connects until a matching call arrives, a call that arrives while the
connect is in flight waits for it, and that wait is bounded: an unreachable
target disconnects the call after the connect timeout.
"""

import re
import time

import pytest
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports,
    finish_harness,
    start_instance,
    switch_show,
    wait_for,
    wait_for_tunnels_active,
)

# reconnect-interval= (seconds) used in these tests instead of the 5s default.
RECONNECT_INTERVAL = 1

# connect-timeout= (seconds) for tests tied to a slow SCCRP or to the deadline
# (daemon default: 10).
CONNECT_TIMEOUT = 6.0

# Shorter connect-timeout= for the test where the budget only bounds the wait.
# Kept above the reconnect cadence so a retry still lands inside it.
SHORT_CONNECT_TIMEOUT = 3.0

# idle-linger= (seconds) for tests that wait for a tunnel to close by itself
# (daemon default: 20).
IDLE_LINGER = 2.0


def _wait_for_show(accel_cmd, needle, timeout, cli_port):
    """Poll `l2tp switch show` until `needle` appears; return (found, elapsed, out)."""
    started = time.monotonic()
    out = [""]

    def seen():
        out[0] = switch_show(accel_cmd, cli_port)
        return needle in out[0]

    found = bool(wait_for(seen, timeout))
    return found, time.monotonic() - started, out[0]


def _events(out):
    """Return {event-name: {round: monotonic-timestamp}} from the harness log."""
    events = {}
    for m in re.finditer(r"event=(\S+) round=(\d+) t=([\d.]+)", out):
        events.setdefault(m.group(1), {})[int(m.group(2))] = float(m.group(3))
    return events


def _timestamps(out):
    """Return {event-name: monotonic-timestamp} for the round-less upstream events."""
    return {
        m.group(1): float(m.group(2))
        for m in re.finditer(r"event=(\S+) t=([\d.]+)", out)
    }


@pytest.mark.l2tp_switch
def test_on_demand_target_stays_down_until_a_call_needs_it(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    # A reachable downstream; the target stays unconnected only because of
    # on-demand mode.
    d_cli, d_port, s_cli, s_port = alloc_ports(4)
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, d_cli, "127.0.0.1", d_port, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            s_cli,
            "127.0.0.1",
            s_port,
            "upstreamsecret",
            extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{d_port},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,downstream
    reconnect-interval={RECONNECT_INTERVAL}
    """,
        )
        assert s_started

        try:
            # Several reconnect intervals; an eagerly connecting target would be [up].
            time.sleep(3 * RECONNECT_INTERVAL)
            out = switch_show(accel_cmd, s_cli)
            assert "[idle]" in out, f"on-demand target connected with no call:\n{out}"
            assert "placed: 0" in out, out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    # Keep the upstream socket open so the test measures the switch, not the
                    # harness exit.
                    "--hold-seconds", "4",
                ],
            )

            up, up_after, out = _wait_for_show(accel_cmd, "[up]", 5.0, s_cli)
            assert up, f"on-demand target never connected after a call arrived:\n{out}"
            placed, placed_after, out = _wait_for_show(accel_cmd, "placed: 1", 5.0, s_cli)
            assert placed, f"queued call was never placed downstream:\n{out}"

            rc, harness_out, err = finish_harness(peer_thread, peer_ctrl, 20.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            # The call triggers the connect, so it must complete promptly, not on a
            # later reconnect tick.
            assert up_after < 3.0, f"target took {up_after:.1f}s to connect after a call"
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=s_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=d_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_call_queues_while_tunnel_is_connecting(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    # A slow downstream: --listen answers the outbound SCCRQ only after
    # --sccrp-delay-ms. The triggering call must wait for it, not be rejected.
    sccrp_delay = 1.5
    s_cli, s_port, down_port = alloc_ports(3)

    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        s_cli,
        "127.0.0.1",
        s_port,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=slow,127.0.0.1,{down_port},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,slow
    connect-timeout={int(CONNECT_TIMEOUT)}
    reconnect-interval={RECONNECT_INTERVAL}
    """,
    )
    assert s_started

    try:
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
                "--rounds", "1",
            ],
        )

        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    # Outlives the stalled connect so the queued call is still live.
                    "--hold-seconds", "4",
                ],
            )
            call_started = time.monotonic()

            # Mid-connect: the call is queued, not placed and not given up on.
            time.sleep(sccrp_delay / 2)
            out = switch_show(accel_cmd, s_cli)
            assert "placed: 0" in out, (
                "call was placed (or dropped) before the target's tunnel"
                f" finished connecting:\n{out}"
            )

            placed, _, out = _wait_for_show(accel_cmd, "placed: 1", 6.0, s_cli)
            placed_after = time.monotonic() - call_started
            assert placed, (
                "queued call was never placed once the slow tunnel came up"
                f"; it was dropped instead of waiting:\n{out}"
            )
            assert placed_after > sccrp_delay * 0.8, (
                f"call was placed after only {placed_after:.1f}s, before the"
                f" downstream's {sccrp_delay:.1f}s SCCRP delay could have"
                " elapsed; the queue is not what held it"
            )

            rc, harness_out, err = finish_harness(peer_thread, peer_ctrl, 25.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"
        finally:
            down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 20.0)
            assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

        events = _events(down_out)
        assert 0 in events.get("recv_sccrq", {}), (
            f"switch never connected to the target at all:\n{down_out}"
        )
        assert 0 in events.get("established", {}), (
            f"slow tunnel never reached established:\n{down_out}"
        )
        # The delay really happened on the wire.
        delay = events["established"][0] - events["recv_sccrq"][0]
        assert delay > sccrp_delay * 0.8, (
            f"downstream answered in {delay:.1f}s, not the requested"
            f" {sccrp_delay:.1f}s; the connect was never actually slow"
        )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_call_cdns_after_connect_timeout(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    # Nothing listens on dead_port, so the connect never succeeds. The call
    # must neither hang forever nor fail instantly.
    s_cli, s_port, dead_port = alloc_ports(3)
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        s_cli,
        "127.0.0.1",
        s_port,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=dead,127.0.0.1,{dead_port},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,dead
    connect-timeout={int(SHORT_CONNECT_TIMEOUT)}
    reconnect-interval={RECONNECT_INTERVAL}
    """,
    )
    assert s_started

    try:
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(s_port),
                "--secret", "upstreamsecret",
                "--calling-number", "472913",
                "--wait-cdn",
                # Well past the budget; the test observes when the CDN arrives.
                "--cdn-timeout", "12",
            ],
        )

        rc, out, err = finish_harness(peer_thread, peer_ctrl, 25.0)
        assert rc == 0, (
            "call against an unreachable on-demand target was never"
            f" disconnected (rc={rc}): {err}\n{out}"
        )

        stamps = _timestamps(out)
        assert "sent_iccn" in stamps and "recv_cdn" in stamps, out
        waited = stamps["recv_cdn"] - stamps["sent_iccn"]
        # the call is ended with a CDN (not a StopCCN) and the general error
        assert "event=got_cdn type=cdn res=2 err=6" in out, out

        # Not instant: failing as soon as target->tunnel is NULL would land here in
        # milliseconds.
        assert waited > SHORT_CONNECT_TIMEOUT * 0.7, (
            f"call was disconnected after only {waited:.1f}s; it was never"
            f" given the {SHORT_CONNECT_TIMEOUT:.0f}s connect budget"
        )
        # Bounded: the retry cadence must not extend the timeout. The timer is
        # periodic, so a deadline that is not re-armed fires early, no-ops and only
        # gives up a period later. Anything past ~5.5s means they drifted apart.
        assert waited < SHORT_CONNECT_TIMEOUT + 2.5, (
            f"call hung for {waited:.1f}s before being disconnected --"
            f" the {SHORT_CONNECT_TIMEOUT:.0f}s connect timeout is not bounding it"
        )

        # The target is back at rest: no half-open tunnel, no reconnect cadence.
        at_rest, _, out = _wait_for_show(accel_cmd, "[idle]", 10.0, s_cli)
        assert at_rest, f"target left with a lingering tunnel:\n{out}"

        time.sleep(3 * RECONNECT_INTERVAL)  # several reconnect cadences
        out = switch_show(accel_cmd, s_cli)
        assert "[idle]" in out, (
            f"target kept retrying with no call left to serve:\n{out}"
        )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_second_call_gets_a_full_budget_of_its_own(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """A second call after the first tunnel is gone gets a full connect-timeout
    budget of its own, not what was left of the first call's.
    """
    # Seconds to wait after the first tunnel is gone. The first phase plus this
    # must stay inside the first budget so its timer is still armed.
    gap = 1.0
    s_cli, s_port, down_port = alloc_ports(3)

    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        s_cli,
        "127.0.0.1",
        s_port,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=flaky,127.0.0.1,{down_port},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,flaky
    connect-timeout={int(CONNECT_TIMEOUT)}
    reconnect-interval={RECONNECT_INTERVAL}
    """,
    )
    assert s_started

    try:
        # One round: the downstream accepts the tunnel and hangs it up at once, so
        # the target goes cold with the first budget's timer still armed.
        #
        # --send-stopccn ends the tunnel as soon as it is established. Without it
        # the switch would only notice the dead peer when the idle linger fires,
        # after the first timer has already expired.
        #
        # --hold-seconds keeps the harness socket open so the switch's ICRQ, sent
        # right after the SCCCN, does not hit a closed port and leave the call
        # unplaced (seen under ASan).
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--send-stopccn",
                "--hold-seconds", "2",
            ],
        )

        first_thread, first_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(s_port),
                "--secret", "upstreamsecret",
                "--calling-number", "472913",
            ],
        )
        finish_harness(first_thread, first_ctrl, 20.0)
        finish_harness(down_thread, down_ctrl, 20.0)

        placed, _, out = _wait_for_show(accel_cmd, "placed: 1", 6.0, s_cli)
        assert placed, f"first call was never placed:\n{out}"

        # Well inside the first budget, so its timer is still armed.
        time.sleep(gap)

        second_thread, second_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(s_port),
                "--secret", "upstreamsecret",
                "--calling-number", "472913",
                "--wait-cdn",
                "--cdn-timeout", "15",
            ],
        )
        rc, out, err = finish_harness(second_thread, second_ctrl, 25.0)
        assert rc == 0, f"second call was never disconnected (rc={rc}): {err}\n{out}"

        stamps = _timestamps(out)
        assert "sent_iccn" in stamps and "recv_cdn" in stamps, out
        waited = stamps["recv_cdn"] - stamps["sent_iccn"]

        # An inherited budget would land at whatever was left of the first one
        # (about half). A fresh budget lands at the full CONNECT_TIMEOUT.
        assert waited > CONNECT_TIMEOUT * 0.7, (
            f"second call was disconnected after {waited:.1f}s; it"
            f" inherited what was left of the first call's budget instead of"
            f" getting its own {CONNECT_TIMEOUT:.0f}s"
        )
        # Upper bound: an inherited timer fires early, no-ops on the deadline
        # check, and only disconnects a period later (~2x the budget).
        assert waited < CONNECT_TIMEOUT + 2.5, (
            f"second call hung for {waited:.1f}s before being disconnected --"
            " its budget's timer is not armed to its own deadline"
        )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_tunnel_that_beats_the_deadline_is_never_orphaned(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """A tunnel that establishes just as its connect budget expires must still
    end up with something that will close it.

    The timeout releases target->tunnel before scheduling the abort into the
    tunnel's context. If the SCCRP is processed in between, the tunnel
    establishes but the abort may not tear it down, leaving a tunnel no call or
    idle linger can reach. The downstream answers ~100ms before the 6s budget
    expires but buries its SCCRP in a 400ms flood of junk datagrams
    (--sccrp-storm-ms), so the deadline fires in the middle of it.

    The assertion is the invariant: no l2tp tunnel is still active a linger
    later.
    """
    sccrp_delay = CONNECT_TIMEOUT - 0.1
    storm = 0.4
    s_cli, s_port, down_port = alloc_ports(3)

    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        s_cli,
        "127.0.0.1",
        s_port,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=racy,127.0.0.1,{down_port},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,racy
    connect-timeout={int(CONNECT_TIMEOUT)}
    idle-linger={int(IDLE_LINGER)}
    reconnect-interval={RECONNECT_INTERVAL}
    """,
    )
    assert s_started

    try:
        # Outlast the whole observation window below.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
                "--sccrp-storm-ms", str(int(storm * 1000)),
                "--rounds", "1",
                "--hold-seconds", "25",
            ],
        )

        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                    "--cdn-timeout", "15",
                ],
            )
            rc, out, err = finish_harness(peer_thread, peer_ctrl, 25.0)
            if rc != 0:
                # The race needs the budget to expire before the downstream
                # answers. A downstream that saw the ICRQ was answered in time
                # (a slow or emulated host stretches the timers unevenly), so
                # the call was placed and nothing ever sends the CDN: the
                # precondition cannot hold on this host, which is not a
                # failure of the code under test.
                _, early_out, _ = finish_harness(down_thread, down_ctrl, 5.0)
                if "event=recv_icrq" in early_out:
                    pytest.skip(
                        "the downstream answered before the connect budget"
                        " expired, so the call was placed instead of timing"
                        " out; the timing this test needs does not hold here"
                    )
            assert rc == 0, (
                f"call against the slow target was never disconnected (rc={rc}):"
                f" {err}\n{out}"
            )
            stamps = _timestamps(out)
            # The budget expired on this call, so the connect timeout released the
            # target's slot. Without that there is no race.
            assert "recv_cdn" in stamps, (
                "the call was placed instead of timing out; the downstream"
                f" answered too early for this test's timing:\n{out}"
            )

            # The CDN goes out when the budget expires, before the flood ends. Let the
            # downstream tunnel finish establishing before reading the tunnel count.
            time.sleep(storm + 2.0)

            # An orphan stays at 1 forever; an aborted tunnel is gone within
            # milliseconds; a re-claimed one closes after one idle linger.
            settled, after, count = wait_for_tunnels_active(
                accel_cmd, 0, IDLE_LINGER + 12.0, cli_port=s_cli
            )
            assert settled, (
                f"{count} l2tp tunnel(s) still active {after:.0f}s after the"
                " on-demand connect timed out; a tunnel that established"
                " just as its budget expired was left with no call able to"
                " reach it and no idle linger able to close it"
            )
        finally:
            # Short: the harness has either exited on the StopCCN or is stuck waiting
            # for an SCCCN that will not arrive.
            rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 5.0)

        events = _events(down_out)
        if 0 in events.get("established", {}):
            # The switch closed the tunnel itself (result 1) rather than it dying with
            # the daemon.
            assert re.search(r"event=recv_stopccn round=0 [^\n]*res=1", down_out), (
                "the tunnel established after the budget expired but the"
                " switch never closed it; it was orphaned, and only the"
                f" harness's own timeout ended this test:\n{down_out}"
            )
        else:
            print(
                "note: the downstream's SCCRP never established the tunnel,"
                " so this run exercised the plain abort path rather than the"
                " establish-vs-abort ordering"
            )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(s_cfg)
