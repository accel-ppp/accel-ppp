"""apses_finished()/apses_stop() racing their tunnel's teardown.

A plain LNS session is terminated from the CLI while its tunnel's context is
stuck, and the tunnel is freed before the apses_finished() call the terminate
queued into it can run, so that call is cancelled. The session is already gone
when the call is dropped, so there is nothing to leak but the switch's count of
calls in flight (l2tp_switch_hops_pending), which holds a shutdown back: the
test settles the daemon, checks the tunnel was freed as intended, and then
requires a soft shutdown to complete.

The race is forced as in test_switch_leaked_holds.py: the peer never answers
the tunnel's HELLO, so its retransmission timer is due to give up on it and
free the tunnel at a known time, and a flood of junk datagrams from before the
terminate until after that keeps the tunnel's context stuck in its read handler
while the terminate is queued.
"""

import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process, process
from helpers import (
    alloc_ports,
    fd_count,
    fd_targets,
    finish_harness,
    l2tp_finishing,
    read_log,
    show_stat,
    start_instance,
    wait_for,
    wait_udp_bound,
)

# rtimeout=, retransmit=, rtimeout-cap= and hello-interval= (seconds, count,
# seconds, seconds) of the daemon. The HELLO the idle tunnel sends one interval
# after it comes up is never acknowledged, so it is retransmitted after one
# more rtimeout and the tunnel is freed when the timer fires again after two,
# the capped, doubled interval.
RTIMEOUT = 1
RETRANSMIT = 1
RTIMEOUT_CAP = 2
HELLO_INTERVAL = 1
FREE_MS = (HELLO_INTERVAL + RTIMEOUT + min(2 * RTIMEOUT, RTIMEOUT_CAP)) * 1000

# Time after the peer's ICCN at which the CLI terminate is issued: after the
# flood started and before the tunnel is due to be freed, by more than the
# few hundred ms of jitter either way.
TERMINATE_MS = 3000
FLOOD_LEAD_MS = 500
FLOOD_TAIL_MS = 400

SETTLE_TIMEOUT = 75.0
SHUTDOWN_TIMEOUT = 10.0

CALLING_NUMBER = "900001"


def _flood_args():
    """Harness arguments for the flood: no StopCCN (the tunnel must stay in
    ESTB), from FLOOD_LEAD_MS before the terminate until FLOOD_TAIL_MS after
    the tunnel is due to be freed."""
    start = TERMINATE_MS - FLOOD_LEAD_MS
    length = FREE_MS + FLOOD_TAIL_MS - start
    return [
        "--fin-flood", f"{start}:{start}:{length}",
        "--fin-flood-no-stopccn",
        "--fin-flood-on", "iccn",
        "--flood-heavy",
    ]


def _sessions_active(accel_cmd, cli_port):
    """Active control-channel session count. It becomes 1 when ICCN is
    processed, which anchors the timing better than the tunnel coming up."""
    out = show_stat(accel_cmd, cli_port)
    m = re.search(
        r"sessions \(control channels\):\r?\n\s*starting: \d+\r?\n\s*active: (\d+)",
        out,
    )
    assert m, f"couldn't parse session count from show stat:\n{out}"
    return int(m.group(1))


def _assert_nothing_leaked(accel_cmd, s_cli, ctrl, cfg, baseline_fds, what):
    pid = ctrl["process"].pid
    state = {}

    def settled():
        state["finishing"] = l2tp_finishing(accel_cmd, s_cli)
        state["fds"] = fd_count(pid, s_cli)
        return state["finishing"] == (0, 0) and state["fds"] <= baseline_fds

    assert wait_for(settled, SETTLE_TIMEOUT, scale=False), (
        f"{what}: (tunnels, sessions) still finishing = {state['finishing']}"
        f" and {state['fds']} file descriptors open (baseline {baseline_fds})"
        " long after everything was torn down"
        "\n" + "\n".join(fd_targets(pid)) +
        f"\n--- switch log ---\n{read_log(cfg)}"
    )


@pytest.mark.l2tp_switch
def test_apses_finished_lost_to_its_tunnel_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """apses_finished() racing its tunnel's teardown leaves no
    leaked tunnel, session or fd."""
    s_cli, s_port = alloc_ports(2)

    started, thread, ctrl, cfg = start_instance(
        accel_pppd, accel_cmd, s_cli, "127.0.0.1", s_port, "upstreamsecret",
        l2tp_extra=f"""rtimeout={RTIMEOUT}
    retransmit={RETRANSMIT}
    rtimeout-cap={RTIMEOUT_CAP}
    hello-interval={HELLO_INTERVAL}""",
    )
    assert started
    try:
        assert wait_udp_bound(s_port), "the daemon never bound its l2tp socket"

        # One connect and teardown first: the daemon opens an fd lazily on
        # the first call, which would otherwise count as a leak.
        warmup_thread, warmup_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(s_port),
                "--secret", "upstreamsecret",
                "--calling-number", CALLING_NUMBER,
                "--send-stopccn",
            ],
        )
        rc, out, err = finish_harness(warmup_thread, warmup_ctrl, 15.0)
        assert rc == 0, f"warm-up harness failed (rc={rc}): {err}\n{out}"
        assert wait_for(lambda: l2tp_finishing(accel_cmd, s_cli) == (0, 0), 10.0), (
            "warm-up connection never settled before baseline capture"
        )

        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        up_thread, up_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(s_port),
                "--secret", "upstreamsecret",
                "--calling-number", CALLING_NUMBER,
                *_flood_args(),
                "--hold-seconds", "1",
            ],
        )
        try:
            anchor = wait_for(
                lambda: time.monotonic()
                if _sessions_active(accel_cmd, s_cli) == 1
                else False,
                5.0,
                interval=0.02,
            )
            assert anchor, (
                "the plain LNS session never went active"
                f"\n--- log ---\n{read_log(cfg)}"
            )

            target = anchor + TERMINATE_MS / 1000.0
            remaining = target - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)

            rc, out, err = process.run(
                [accel_cmd, "-p", str(s_cli), f"terminate csid {CALLING_NUMBER} hard"]
            )
            assert rc == 0, f"terminate failed (rc={rc}): {err}\n{out}"

            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{out}"
                f"\n--- log ---\n{read_log(cfg)}"
            )
            assert "event=fin_flood_end" in out, out
        finally:
            pass

        _assert_nothing_leaked(
            accel_cmd, s_cli, ctrl, cfg, baseline_fds,
            "apses_finished()'s hop lost to its own tunnel's teardown",
        )

        # The tunnel went away through its retransmission timer, as intended.
        log = read_log(cfg)
        assert "no acknowledgement from peer" in log, log
        # ... without the terminate's call ever running (the warm-up
        # tunnel, logged first, may well have run its own)
        raced = log[log.rindex("handling SCCRQ"):]
        assert "data channel closed, disconnecting session" not in raced, (
            "apses_finished()'s call into the tunnel ran instead of being"
            f" dropped with the tunnel\n--- log ---\n{log}"
        )

        # A call dropped with its tunnel still counts as in flight until its
        # cancel accounts for it, and a shutdown waits for those.
        rc, out, err = process.run([accel_cmd, "-p", str(s_cli), "shutdown soft"])
        assert rc == 0, f"shutdown soft failed (rc={rc}): {err}\n{out}"
        assert wait_for(
            lambda: ctrl["process"].poll() is not None, SHUTDOWN_TIMEOUT
        ), (
            "the daemon never completed a soft shutdown after the dropped call"
            f"\n--- log ---\n{read_log(cfg)}"
        )
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(cfg)
