"""l2tp-switch: references taken for a cross-context call must not outlive it.

The switch hands work to another tunnel's triton context with
triton_context_call() after taking a reference on whatever the call will
touch. triton_context_unregister() frees queued calls without running them,
so if the tunnel is freed first (FIN_WAIT timer, StopCCN, retransmission
exhaustion) the references are never released and the tunnel or session
leaks along with its descriptors.

Each test forces that ordering with the peer harness's --fin-flood: a StopCCN
puts the tunnel in FIN_WAIT, and a flood of junk datagrams keeps its context
busy in l2tp_conn_read() while the switch timer schedules the call under test
and the FIN_WAIT timer expires. See l2tp_switch_peer_flood.c.

The tests assert the invariant: after settling, no tunnel or session is left
in a "finishing" state and the daemon holds no more file descriptors than
before. They fail only on a leak.
"""

import contextlib
import re

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports,
    fd_count,
    fd_targets,
    finish_harness,
    RaceNotReached,
    l2tp_finishing,
    read_log,
    run_until_race_reached,
    start_instance,
    wait_for,
    wait_for_tunnels_active,
    wait_udp_bound,
)

# connect-timeout= and idle-linger= (seconds) of the default configuration;
# the tests that need other values pass them to _switch().
CONNECT_TIMEOUT = 3
IDLE_LINGER = 4

# rtimeout=, retransmit= and rtimeout-cap= (seconds, count, seconds). With the
# default retransmit count a tunnel stays in FIN_WAIT for one full cycle of
# the capped, doubling backoff, 1 + 2 = 3s instead of 31s, see
# l2tp_tunnel_finwait(). The FAST count is for the tests that need a tunnel
# whose peer never acknowledges a message to give up after 3s too.
RTIMEOUT = 1
RETRANSMIT = 2
FAST_RETRANSMIT = 1
RTIMEOUT_CAP = 2


def _backoff_ms(intervals):
    """Sum of the first `intervals` capped, doubling retransmit intervals."""
    total, rtimeout = 0, RTIMEOUT
    for _ in range(intervals):
        total += rtimeout
        rtimeout = min(rtimeout * 2, RTIMEOUT_CAP)
    return total * 1000


FIN_WAIT_MS = _backoff_ms(RETRANSMIT)
# A tunnel whose peer never acknowledges a message is freed by its
# retransmission timer firing once more than `retransmit` times.
UNACKED_FREE_MS = _backoff_ms(FAST_RETRANSMIT + 1)

# Margins around the moment the switch's timer schedules its call, all far
# outside the few ms of jitter either way: the flood is already running that
# long before it, the FIN_WAIT timer expires that long after the call is
# scheduled, and the flood outlasts that expiry by the tail.
FLOOD_LEAD_MS = 300
FIN_WAIT_AFTER_MS = 300
FLOOD_TAIL_MS = 400
# The same for the floods that keep a context stuck in its read handler: they
# start after the first retransmission (at RTIMEOUT) and well before the
# switch's timer, and end after the last one is due.
STUCK_LEAD_MS = 500
# Time of the switch's timer, from the SCCRQ / the call's CDN, in those tests.
STUCK_DEADLINE_MS = 2000


def _fin_flood(deadline_ms):
    """Return the harness's --fin-flood A:S:W for a tunnel that is freed
    FIN_WAIT_AFTER_MS after a switch timer due `deadline_ms` after the anchor
    event: the StopCCN goes out early enough for that."""
    stopccn = deadline_ms + FIN_WAIT_AFTER_MS - FIN_WAIT_MS
    start = deadline_ms - FLOOD_LEAD_MS
    length = FLOOD_LEAD_MS + FIN_WAIT_AFTER_MS + FLOOD_TAIL_MS
    return f"{stopccn}:{start}:{length}"


def _stuck_flood_args(deadline_ms=STUCK_DEADLINE_MS):
    """Harness arguments (besides --fin-flood-on) for a flood that keeps a
    tunnel's context inside its read handler from before a switch timer due
    `deadline_ms` after the anchor event until after the tunnel's
    retransmission timer is due to give up on the message it never gets an
    answer to.

    The context does not process anything else meanwhile, so the call the
    switch's timer queues is still pending when the tunnel is freed, which
    is what hands the call to its cancel callback. A StopCCN cannot do this:
    a tunnel in FIN_WAIT has already let go of its target."""
    start = deadline_ms - STUCK_LEAD_MS
    length = UNACKED_FREE_MS + FLOOD_TAIL_MS - start
    return [
        "--fin-flood", f"{start}:{start}:{length}",
        "--fin-flood-no-stopccn",
        "--flood-heavy",
    ]


def _event_time(output, name):
    """Monotonic timestamp (s) of the first `event=<name> ... t=<ts>` line."""
    m = re.search(rf"event={name}\b.*?\bt=([0-9.]+)", output)
    assert m, f"no {name} event in:\n{output}"
    return float(m.group(1))


@contextlib.contextmanager
def _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port, peer_bin,
            retransmit=RETRANSMIT, connect_timeout=CONNECT_TIMEOUT,
            idle_linger=IDLE_LINGER):
    """An on-demand switch instance; yields (ctrl, cfg)."""
    started, thread, ctrl, cfg = start_instance(
        accel_pppd,
        accel_cmd,
        s_cli,
        "127.0.0.1",
        s_port,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=leaky,127.0.0.1,{down_port},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,leaky
    connect-timeout={connect_timeout}
    idle-linger={idle_linger}
    reconnect-interval=1
    """,
        # Two threads, not one: with one, a flood that keeps one context busy
        # starves the switch's own timers (on the default context) as well.
        thread_count=2,
        l2tp_extra=f"""rtimeout={RTIMEOUT}
    retransmit={retransmit}
    rtimeout-cap={RTIMEOUT_CAP}""",
    )
    assert started
    try:
        # Warm up with one full call through to a real downstream before any
        # test measures baseline_fds, so one-off descriptors opened by the
        # first call are not counted as leaks.
        #
        # The downstream must outlive the target's idle linger plus the StopCCN
        # round trip at its end. If it exits first, the switch sees a failed
        # target and backs off before the next call.
        warmup_down_thread, warmup_down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--hold-seconds", str(idle_linger + 8),
            ],
        )
        try:
            assert wait_udp_bound(down_port), (
                "the warm-up downstream harness never bound"
            )
            warmup_up_thread, warmup_up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--send-stopccn",
                ],
            )
            rc, out, err = finish_harness(warmup_up_thread, warmup_up_ctrl, 15.0)
            assert rc == 0, (
                f"warm-up upstream harness failed (rc={rc}): {err}\n{out}"
            )

            assert wait_for(
                lambda: l2tp_finishing(accel_cmd, s_cli) == (0, 0), 10.0
            ), "warm-up call's upstream-facing session/tunnel never settled"
            # Let the downstream leg go only after the switch has sent it a graceful
            # StopCCN, i.e. once the target is idle again.
            assert wait_for_tunnels_active(
                accel_cmd, 0, idle_linger + 5.0, s_cli
            )[0], "warm-up call's on-demand target tunnel never went idle"
        finally:
            finish_harness(warmup_down_thread, warmup_down_ctrl, 15.0)

        yield ctrl, cfg
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(cfg)


# How long to wait for the switch to finish everything it tore down. A leak
# never resolves, so this only bounds how long a failing test takes; but it
# must outlast a tunnel whose peer has gone away: the upstream harness exits
# right after the CDN without acking the switch's StopCCN, and that tunnel
# then retransmits it (1+2 s of backoff, then a last wait) before it gives up.
SETTLE_TIMEOUT = 75.0


def _assert_nothing_leaked(accel_cmd, s_cli, ctrl, cfg, baseline_fds, what):
    """Everything torn down has been destroyed, and its descriptors closed."""
    pid = ctrl["process"].pid
    state = {}

    def settled():
        state["finishing"] = l2tp_finishing(accel_cmd, s_cli)
        state["fds"] = fd_count(pid, s_cli)
        return state["finishing"] == (0, 0) and state["fds"] <= baseline_fds

    assert wait_for(settled, SETTLE_TIMEOUT, scale=False), (
        f"{what}: (tunnels, sessions) still finishing = {state['finishing']}"
        f" and {state['fds']} file descriptors open (baseline {baseline_fds})"
        " long after everything was torn down; a reference taken for a"
        " cross-context call was never released"
        "\n" + "\n".join(fd_targets(pid)) +
        f"\n--- switch log ---\n{read_log(cfg)}"
    )


@pytest.mark.l2tp_switch
def test_abort_of_stalled_tunnel_lost_to_its_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """See _abort_attempt(); repeated until the race is reached."""
    run_until_race_reached(
        lambda: _abort_attempt(accel_cmd, accel_pppd, peer_bin)
    )


def _abort_attempt(accel_cmd, accel_pppd, peer_bin):
    """The connect timeout schedules l2tp_switch_abort_stalled_tunnel() into
    the stalled tunnel's context under a tunnel_hold(); if the tunnel is
    freed first, the hold must still be released.

    The stalled tunnel (its SCCRQ is never answered) is stuck in its read
    handler by a flood from before the connect timeout until after its
    retransmission timer is due to give up on the SCCRQ and free it, so the
    abort is still queued when that happens."""
    s_cli, s_port, down_port = alloc_ports(3)
    connect_timeout = STUCK_DEADLINE_MS // 1000

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port, peer_bin,
                 retransmit=FAST_RETRANSMIT,
                 connect_timeout=connect_timeout) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                *_stuck_flood_args(),
                "--fin-flood-on", "sccrq",
                "--hold-seconds", "1",
            ],
        )
        try:
            assert wait_udp_bound(down_port), "the downstream harness never bound"
            up_thread, up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                    "--cdn-timeout", "20",
                ],
            )
            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"the call was never disconnected (rc={rc}): {err}\n{out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
        finally:
            down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)
            assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

        assert "event=fin_flood_end" in down_out, (
            f"the downstream never ran its flood:\n{down_out}\n{down_err}"
        )
        # The race was hit: the connect timeout (it disconnects the queued
        # call, whose CDN the upstream sees) fired while the stalled tunnel
        # was alive and stuck, well before its retransmission timer gave up.
        sccrq = _event_time(down_out, "recv_sccrq")
        cdn = _event_time(out, "recv_cdn")
        if not (connect_timeout - 0.2 <= cdn - sccrq
                <= UNACKED_FREE_MS / 1000.0 - 0.5):
            raise RaceNotReached(
                f"the connect timeout fired {cdn - sccrq:.2f}s after the SCCRQ"
                f"\n--- downstream harness ---\n{down_out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
        if _event_time(down_out, "fin_flood_end") - sccrq < (
            UNACKED_FREE_MS / 1000.0
        ):
            raise RaceNotReached(
                f"the flood ended too early\n{down_out}"
            )
        _assert_nothing_leaked(
            accel_cmd, s_cli, ctrl, cfg, baseline_fds,
            "stalled tunnel torn down before its abort ran",
        )


@pytest.mark.l2tp_switch
def test_disconnect_of_queued_call_lost_to_its_tunnel_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The connect timeout schedules l2tp_switch_disconnect_upstream() into
    each queued call's upstream tunnel under a hold on the session; if that
    tunnel is freed first, the session and tunnel must still be released."""
    s_cli, s_port, down_port = alloc_ports(3)

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port, peer_bin) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        # Never answers, so the call stays queued until the connect timeout.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--sccrp-delay-ms", "600000",
                "--hold-seconds", "1",
            ],
        )
        try:
            assert wait_udp_bound(down_port), "the downstream harness never bound"
            # The upstream LAC ends its own tunnel and floods it, anchored on the
            # ICCN that queued the call. This is the inbound-facing tunnel.
            up_thread, up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--fin-flood",
                    _fin_flood(CONNECT_TIMEOUT * 1000),
                    "--fin-flood-on", "iccn",
                    "--hold-seconds", "1",
                ],
            )
            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
            assert "event=fin_flood_end" in out, out

            # The abort sends StopCCN to the still-negotiating downstream tunnel.
            # Dead peer: stop it retransmitting for ~30s.
            down_ctrl["process"].kill()

            _assert_nothing_leaked(
                accel_cmd, s_cli, ctrl, cfg, baseline_fds,
                "queued call's tunnel torn down before its disconnect ran",
            )
        finally:
            finish_harness(down_thread, down_ctrl, 5.0)


@pytest.mark.l2tp_switch
def test_idle_close_lost_to_its_tunnel_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """See _idle_close_attempt(); repeated until the race is reached."""
    run_until_race_reached(
        lambda: _idle_close_attempt(accel_cmd, accel_pppd, peer_bin)
    )


def _idle_close_attempt(accel_cmd, accel_pppd, peer_bin):
    """The idle linger schedules l2tp_switch_close_idle_tunnel() into the
    target tunnel's context under a tunnel_hold(); if the tunnel is freed
    first, the hold must still be released.

    The downstream never acknowledges the CDN that ended the call, so the
    target tunnel's retransmission timer is due to give up on it and free the
    tunnel a few seconds later. A flood from before the linger expires until
    after that keeps the tunnel's context stuck, so the close is still queued
    when it happens."""
    s_cli, s_port, down_port = alloc_ports(3)
    idle_linger = STUCK_DEADLINE_MS // 1000

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port, peer_bin,
                 retransmit=FAST_RETRANSMIT,
                 idle_linger=idle_linger) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        # The flood is anchored on the CDN the switch sends when the call
        # ends, which is also when the linger starts.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                *_stuck_flood_args(),
                "--fin-flood-on", "cdn",
                "--no-ack-cdn",
                "--hold-seconds", "1",
            ],
        )
        try:
            assert wait_udp_bound(down_port), "the downstream harness never bound"
            up_thread, up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", "SWITCHOK",
                    "--send-stopccn",
                ],
            )
            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
        finally:
            rc, down_out, down_err = finish_harness(
                down_thread, down_ctrl, idle_linger + 15.0
            )

        assert "event=recv_cdn" in down_out and "event=fin_flood_end" in down_out, (
            "the call never ended on the downstream leg, or its flood never"
            f" ran:\n{down_out}\n{down_err}\n--- switch log ---\n{read_log(cfg)}"
        )
        # The flood outlasted the point where the tunnel gives up on the CDN,
        # and the linger expired while the context was stuck: the close never
        # ran (it would have logged, as the warm-up call's did).
        if _event_time(down_out, "fin_flood_end") - _event_time(
            down_out, "recv_cdn"
        ) < UNACKED_FREE_MS / 1000.0:
            raise RaceNotReached(f"the flood ended too early\n{down_out}")
        # A flooded context that momentarily drained its socket ran the
        # queued close before the tunnel was freed: not the race under test.
        if read_log(cfg).count("closing on-demand tunnel") != 1:
            raise RaceNotReached(
                "the idle close ran instead of being cancelled"
                f"\n--- downstream harness ---\n{down_out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
        _assert_nothing_leaked(
            accel_cmd, s_cli, ctrl, cfg, baseline_fds,
            "idle tunnel torn down before its linger close ran",
        )
