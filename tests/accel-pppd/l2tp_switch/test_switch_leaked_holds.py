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

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports,
    fd_count,
    fd_targets,
    finish_harness,
    l2tp_finishing,
    read_log,
    start_instance,
    wait_for,
    wait_for_tunnels_active,
    wait_udp_bound,
)

# connect-timeout= and idle-linger= (seconds) used in the configs below.
CONNECT_TIMEOUT = 3
IDLE_LINGER = 4

# Time the switch's own target tunnel (switch_target set) stays in FIN_WAIT
# after a peer StopCCN: one rtimeout (1s by default).
FIN_WAIT_MS = 1000

# The disconnect test floods the switch's inbound-facing tunnel instead. It has
# no switch_target, so it uses the full retransmit backoff rather than
# FIN_WAIT_MS. _switch() shrinks these so the backoff is 1 + 2 = 3s instead
# of 31s.
UPSTREAM_RTIMEOUT = 1
UPSTREAM_RETRANSMIT = 2
UPSTREAM_RTIMEOUT_CAP = 2
UPSTREAM_FIN_WAIT_MS = 3000

# Margins around the moment the switch's timer schedules its call, all far
# outside the few ms of jitter either way: the flood is already running that
# long before it, the FIN_WAIT timer expires that long after it, and the
# flood outlasts that expiry by the tail.
FLOOD_LEAD_MS = 300
FIN_WAIT_AFTER_MS = 300
FLOOD_TAIL_MS = 400

# How long to wait for the switch to finish everything it tore down. A leak
# never resolves, so this only bounds how long a failing test takes; but it
# must outlast a tunnel whose peer has gone away: the upstream harness exits
# right after the CDN without acking the switch's StopCCN, and that tunnel
# then retransmits it (1+2+4+8+16 s of backoff, then a last wait) before it
# gives up, some 47 s with the default retransmit settings.
SETTLE_TIMEOUT = 75.0


def _fin_flood(deadline_ms, fin_wait_ms=FIN_WAIT_MS):
    """Return the harness's --fin-flood A:S:W for a switch timer due
    `deadline_ms` after the anchor event.

    `fin_wait_ms` is how long the flooded tunnel stays in FIN_WAIT:
    FIN_WAIT_MS for a switch target tunnel, UPSTREAM_FIN_WAIT_MS for the
    inbound-facing one."""
    stopccn = deadline_ms + FIN_WAIT_AFTER_MS - fin_wait_ms
    start = deadline_ms - FLOOD_LEAD_MS
    length = FLOOD_LEAD_MS + FIN_WAIT_AFTER_MS + FLOOD_TAIL_MS
    return f"{stopccn}:{start}:{length}"


@contextlib.contextmanager
def _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port, peer_bin):
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
    connect-timeout={CONNECT_TIMEOUT}
    idle-linger={IDLE_LINGER}
    reconnect-interval=1
    """,
        # Pinned to remove cross-thread scheduling as a variable on multi-vCPU hosts.
        thread_count=1,
        l2tp_extra=f"""rtimeout={UPSTREAM_RTIMEOUT}
    retransmit={UPSTREAM_RETRANSMIT}
    rtimeout-cap={UPSTREAM_RTIMEOUT_CAP}""",
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
                "--hold-seconds", str(IDLE_LINGER + 8),
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
                accel_cmd, 0, IDLE_LINGER + 5.0, s_cli
            )[0], "warm-up call's on-demand target tunnel never went idle"
        finally:
            finish_harness(warmup_down_thread, warmup_down_ctrl, 15.0)

        yield ctrl, cfg
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(cfg)


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
    """The connect timeout schedules l2tp_switch_abort_stalled_tunnel() into
    the stalled tunnel's context under a tunnel_hold(); if the tunnel is
    freed first, the hold must still be released."""
    s_cli, s_port, down_port = alloc_ports(3)

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port, peer_bin) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        # The downstream never answers, so the tunnel stays in WAIT_SCCRP until the
        # connect timeout. The harness anchors on the SCCRQ it sees.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--fin-flood", _fin_flood(CONNECT_TIMEOUT * 1000),
                "--fin-flood-on", "sccrq",
                "--hold-seconds", "3",
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
            rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)

        assert "event=fin_flood_end" in down_out, (
            f"the downstream never ran its flood:\n{down_out}\n{down_err}"
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
            # ICCN that queued the call. This is the inbound-facing tunnel, so
            # UPSTREAM_FIN_WAIT_MS applies.
            up_thread, up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--fin-flood",
                    _fin_flood(CONNECT_TIMEOUT * 1000,
                              fin_wait_ms=UPSTREAM_FIN_WAIT_MS),
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
    """The idle linger schedules l2tp_switch_close_idle_tunnel() into the
    target tunnel's context under a tunnel_hold(); if the tunnel is freed
    first (here by the downstream's StopCCN), the hold must still be
    released."""
    s_cli, s_port, down_port = alloc_ports(3)

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port, peer_bin) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        # A patient downstream that stays up after the call ends. The flood is
        # anchored on the CDN the switch sends then, when the linger starts.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--fin-flood", _fin_flood(IDLE_LINGER * 1000),
                "--fin-flood-on", "cdn",
                "--hold-seconds", "60",
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
                down_thread, down_ctrl, IDLE_LINGER + 15.0
            )

        assert "event=recv_cdn" in down_out and "event=fin_flood_end" in down_out, (
            "the call never ended on the downstream leg, or its flood never"
            f" ran:\n{down_out}\n{down_err}\n--- switch log ---\n{read_log(cfg)}"
        )
        _assert_nothing_leaked(
            accel_cmd, s_cli, ctrl, cfg, baseline_fds,
            "idle tunnel torn down before its linger close ran",
        )
