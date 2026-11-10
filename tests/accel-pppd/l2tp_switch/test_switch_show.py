import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports, start_instance, switch_show, finish_harness,
    wait_for, wait_for_tunnels_active, wait_up,
)

DATA_PATTERN = "SWITCHOK"


def _events(out):
    """Return [(event-name, timestamp), ...] as the --listen harness logged them."""
    return [
        (m.group(1), float(m.group(2)))
        for m in re.finditer(r"event=(\S+) round=\d+ t=([\d.]+)", out)
    ]


def _times(events, name):
    return [t for (event, t) in events if event == name]

# Must match idle-linger= in the [l2tp-switch] configs below.
IDLE_LINGER = 8.0


@pytest.mark.l2tp_switch
# One worker thread is what triton uses on a 1-CPU host (the 1-vCPU QEMU CI
# legs). The per-call lines must still appear there.
@pytest.mark.parametrize("thread_count", [None, 1], ids=["default-threads", "one-worker-thread"])
def test_switch_show_lists_per_session_line(pytestconfig, accel_cmd, accel_pppd, peer_bin, thread_count):
    switch_cli, down_cli, switch_l2tp, down_l2tp = alloc_ports(4)
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, down_cli, "127.0.0.1", down_l2tp, "downstreamsecret"
    )
    assert d_started

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
    # Persistent target, so its tunnel is already up when the call arrives.
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
            thread_count=thread_count,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                    # Keep the upstream call alive while `show` is polled, so the per-call
                    # line does not vanish when the harness exits. The harness is joined below.
                    "--hold-seconds", "40",
                ],
            )
            out_box = [""]
            try:
                _, out = _wait_show(accel_cmd, switch_cli, "call: 472913", 10.0)
                assert "call: 472913" in out, out
                # bytes_out counts the splice data; wait for it too
                wait_for(lambda: _bytes_out(_show_into(out_box, accel_cmd, switch_cli)) >= len(DATA_PATTERN), 10.0)
                out = out_box[0]
            finally:
                rc, hout, err = finish_harness(peer_thread, peer_ctrl, 60.0)
            assert rc == 0, err

            # per-target line: active count (the harness write travels target-bound)
            assert "active=1" in out, out

            # per-call line: both tunnel/session ID pairs as "tid-sid / tid-sid", and
            # at least len("SWITCHOK") bytes (>= in case control bytes inflate it).
            call_line = next(
                line for line in out.splitlines() if line.strip().startswith("call:")
            )
            # nested under its target line
            assert call_line.startswith("    call:"), repr(call_line)
            bytes_out = int(call_line.split("bytes_out=")[1].split()[0])
            assert bytes_out >= len(DATA_PATTERN), call_line
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


def _show_into(box, accel_cmd, cli_port):
    box[0] = switch_show(accel_cmd, cli_port)
    return box[0]


def _bytes_out(out):
    m = re.search(r"call:.*bytes_out=(\d+)", out)
    return int(m.group(1)) if m else -1


def _wait_show(accel_cmd, cli_port, needle, timeout):
    """Poll `l2tp switch show` until `needle` appears; return (found, out)."""
    out = [""]

    def seen():
        out[0] = switch_show(accel_cmd, cli_port)
        return needle in out[0]

    return bool(wait_for(seen, timeout)), out[0]


@pytest.mark.l2tp_switch
def test_switch_show_on_demand_states(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """`l2tp switch show` status word for an on-demand target through connect,
    busy, idle-lingering and closed:

      [idle]        at rest
      [connecting]  while negotiating (best effort, not asserted)
      [up]          while a call is active
      [idle]        after the call ends, tunnel still lingering
      [idle]        once the linger has closed the tunnel

    The last two share a word, so `show stat`'s tunnel count tells them apart.
    The downstream is the peer harness in --listen --hold-seconds mode because a
    real accel-ppp downstream closes within about a second of the call ending.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "60",
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
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    idle-linger=8
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            out = switch_show(accel_cmd, switch_cli)
            assert "[idle]" in out, f"on-demand target connected with no call:\n{out}"

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                    "--send-stopccn",
                ],
            )

            # --send-stopccn ends the call right after the handshake, so how long
            # [up]/active=1 stays visible depends on a race. The live poll is best
            # effort; the downstream peer's record shows the target connected on demand.
            saw_up = False
            saw_active = False

            def watch():
                nonlocal saw_up, saw_active
                out = switch_show(accel_cmd, switch_cli)
                if "[up]" in out:
                    saw_up = True
                if "active=1" in out:
                    saw_active = True
                # done once the call was seen and is over, or the harness has finished
                return saw_up or (saw_active and "active=0" in out) or \
                    peer_ctrl["process"].poll() is not None

            wait_for(watch, 8.0, interval=0.05)

            rc, harness_out, err = finish_harness(peer_thread, peer_ctrl, 60.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            idle, out = _wait_show(accel_cmd, switch_cli, "active=0", 15.0)
            assert idle, f"call never ended:\n{out}"
            assert "[idle]" in out, out

            # The linger is asserted below from the downstream peer's timestamps,
            # because a client-side check lags the daemon on a slow runner.
            closed, _, n = wait_for_tunnels_active(accel_cmd, 0, IDLE_LINGER + 30.0, switch_cli)
            assert closed, (
                f"tunnel never closed after its idle linger (tunnels"
                f" active={n})"
            )
            out = switch_show(accel_cmd, switch_cli)
            assert "[idle]" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = l2tp_peer_process.wait(down_thread, down_ctrl, 60.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"
        assert down_rc is not None, f"downstream harness never finished:\n{down_out}"

    events = _events(down_out)
    cdn = _times(events, "recv_cdn")
    stopccn = _times(events, "recv_stopccn")
    assert len(_times(events, "recv_sccrq")) == 1, f"expected one tunnel:\n{down_out}"
    assert len(_times(events, "recv_icrq")) == 1, f"expected one call:\n{down_out}"
    assert cdn and stopccn, f"downstream never saw the call end and tunnel close:\n{down_out}"
    # The tunnel lingered and closed on the switch's idle-linger, measured on the
    # downstream peer's clock.
    linger = stopccn[0] - cdn[0]
    assert IDLE_LINGER * 0.8 < linger < IDLE_LINGER + 5.0, (
        f"tunnel closed {linger:.1f}s after the call ended, not the"
        f" {IDLE_LINGER:.0f}s linger:\n{down_out}"
    )


# `l2tp switch show` must not list a call as active once its upstream leg
# has finished, even before the deferred l2tp_switch_teardown_peer() hop has
# cleared the peer's pointer (see switch_show_walk() in l2tp.c).
#
# That window is normally one context hop wide. --busy-flood-ms widens it:
# the --listen harness floods its control channel with junk, keeping the
# downstream tunnel context busy so the hop cannot run.
BUSY_FLOOD_MS = 4000
# Poll window after finish_harness() returns. The switch may still be
# processing the upstream StopCCN on a loaded runner, so allow a margin;
# 4s stays under the BUSY_FLOOD_MS flood.
_STALE_POLL_WINDOW_S = 4.0


@pytest.mark.l2tp_switch
def test_switch_show_does_not_list_call_finished_during_teardown_hop(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--busy-flood-ms", str(BUSY_FLOOD_MS),
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

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                    "--send-stopccn",
                ],
            )
            rc, out, err = finish_harness(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, f"upstream harness failed (rc={rc}): {err}\n{out}"

            # The upstream harness has sent its StopCCN and exited, so the hop is
            # scheduled onto the downstream leg's context, which is still busy in the
            # flood. Poll `l2tp switch show` across the rest of the flood: a target
            # showing active=0 must not still list a "call:" line. active=1 with a call
            # line is not stale; the upstream teardown just has not happened yet.
            stale = []
            deadline = time.monotonic() + _STALE_POLL_WINDOW_S
            while time.monotonic() < deadline:
                shown = switch_show(accel_cmd, switch_cli)
                has_call = any(
                    line.strip().startswith("call:") for line in shown.splitlines()
                )
                if "active=0" in shown and has_call:
                    stale.append(shown)
                time.sleep(0.05)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 20.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

    assert "event=recv_icrq" in down_out, (
        "the call was never placed on the downstream leg; broken test"
        f" setup, not the staleness fix:\n{down_out}\n{down_err}"
    )
    assert "event=busy_flood_start" in down_out, (
        f"the downstream harness never ran its busy flood:\n{down_out}"
    )
    assert not stale, (
        "`l2tp switch show` listed a call as still active during the"
        " deferred teardown-peer hop's window, after the upstream leg had"
        " already sent its own StopCCN:\n" + "\n---\n".join(stale)
    )
