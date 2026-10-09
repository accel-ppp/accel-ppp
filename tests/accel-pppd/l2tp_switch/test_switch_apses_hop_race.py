"""apses_finished()/apses_stop() racing their tunnel's teardown.

A plain LNS session is terminated from the CLI while its tunnel's FIN_WAIT
timer is about to expire, so the apses_finished() call into the tunnel context
is queued when the tunnel is freed. The daemon must settle with no leaked
tunnel, session or file descriptor. The session is already gone when the call
is dropped, so the leak check cannot fail on its own; the test mainly exercises
the race under TSAN.

The race is forced as in test_switch_leaked_holds.py: a StopCCN plus a flood of
junk datagrams, both timed from the peer's ICCN, keep the tunnel's context busy
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

# Time after the peer's ICCN at which the CLI terminate is issued and the
# tunnel's FIN_WAIT teardown is aimed. Large enough that the poll for an
# active session is a small part of it.
DEADLINE_MS = 2000

# How long before DEADLINE_MS to issue the terminate, so the queued call is
# still pending when the FIN_WAIT timer fires.
TERMINATE_LEAD_MS = 200

FIN_WAIT_MS = 1000  # StopCCN rtimeout
FLOOD_LEAD_MS = 300
FIN_WAIT_AFTER_MS = 300
FLOOD_TAIL_MS = 400

SETTLE_TIMEOUT = 75.0

CALLING_NUMBER = "900001"


def _fin_flood(deadline_ms):
    """--fin-flood A:S:W argument for a FIN_WAIT teardown `deadline_ms` after
    the peer's ICCN."""
    stopccn = deadline_ms + FIN_WAIT_AFTER_MS - FIN_WAIT_MS
    start = deadline_ms - FLOOD_LEAD_MS
    length = FLOOD_LEAD_MS + FIN_WAIT_AFTER_MS + FLOOD_TAIL_MS
    return f"{stopccn}:{start}:{length}"


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
    """apses_finished() racing its tunnel's FIN_WAIT teardown leaves no
    leaked tunnel, session or fd."""
    s_cli, s_port = alloc_ports(2)

    started, thread, ctrl, cfg = start_instance(
        accel_pppd, accel_cmd, s_cli, "127.0.0.1", s_port, "upstreamsecret",
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
                "--fin-flood", _fin_flood(DEADLINE_MS),
                "--fin-flood-on", "iccn",
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

            target = anchor + (DEADLINE_MS - TERMINATE_LEAD_MS) / 1000.0
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
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(cfg)
