"""on-demand targets: a call arriving while the idle-linger StopCCN is unacked.

The idle linger closes the tunnel with a local StopCCN. Until the peer
acknowledges it the closing tunnel must not hold the target's connect slot: a
call arriving meanwhile has to get a new tunnel at once, not wait for the
acknowledgement, the reconnect timer or the connect timeout.

The downstream is the peer harness with --no-ack-stopccn, which never
acknowledges the StopCCN but still accepts the next SCCRQ.
"""

import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, read_log, start_instance, switch_show, wait_for

# Must match idle-linger= below.
IDLE_LINGER = 1
# Shorter than the unacked StopCCN's own timeout, so the unfixed switch gives
# up on the queued call before anything else frees the connect slot.
CONNECT_TIMEOUT = 3
RECONNECT_INTERVAL = 2
# The new tunnel and call must show up well inside the connect timeout.
PROMPT = 1.0


def _call(peer_bin, port, extra):
    return l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(port),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
        ] + extra,
    )


def _event_times(out, name):
    return [float(t) for t in re.findall(rf"event={name} round=\d+ t=([\d.]+)", out)]


@pytest.mark.l2tp_switch
def test_call_during_unacked_idle_stopccn_gets_a_new_tunnel(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "2",
            "--hold-seconds", "30",
            "--no-ack-stopccn",
        ],
    )
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd, accel_cmd, switch_cli, "127.0.0.1", switch_l2tp, "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    idle-linger={IDLE_LINGER}
    connect-timeout={CONNECT_TIMEOUT}
    reconnect-interval={RECONNECT_INTERVAL}
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    call2_out = ""
    call2_start = 0.0
    try:
        # First call: placed, then ended from the upstream side.
        t1, c1 = _call(peer_bin, switch_l2tp, ["--data-pattern", "SWITCHOK", "--send-stopccn"])
        rc, out, err = l2tp_peer_process.wait(t1, c1, 30.0)
        assert rc == 0, f"first call failed (rc={rc}): {err}\n{out}"
        assert wait_for(lambda: "active: 0" in switch_show(accel_cmd, switch_cli), 15.0)
        ended = time.monotonic()

        # The linger fires IDLE_LINGER after the call ended; the second call
        # arrives shortly after, with the StopCCN still unacknowledged.
        time.sleep(max(0.0, ended + IDLE_LINGER + 0.4 - time.monotonic()))
        call2_start = time.monotonic()
        t2, c2 = _call(peer_bin, switch_l2tp, ["--wait-cdn", "--cdn-timeout", str(CONNECT_TIMEOUT + 2)])
        # Healthy: no CDN, so it ends by its own timeout.
        _, call2_out, _ = l2tp_peer_process.wait(t2, c2, CONNECT_TIMEOUT + 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        switch_log = read_log(s_cfg)
        config.delete_tmp(s_cfg)
        down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 5.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

    assert "event=got_cdn" not in call2_out, (
        f"the call arriving during the unacked StopCCN was disconnected:\n{call2_out}\n{down_out}\n{down_err}\n{switch_log}"
    )
    sccrq = _event_times(down_out, "recv_sccrq")
    icrq = _event_times(down_out, "recv_icrq")
    stopccn = _event_times(down_out, "recv_stopccn")
    assert stopccn, f"the idle tunnel was never closed:\n{down_out}"
    assert len(sccrq) == 2, f"no second tunnel for the second call:\n{down_out}"
    assert sccrq[1] - call2_start < PROMPT, (
        f"second tunnel came {sccrq[1] - call2_start:.2f}s after the call, not"
        f" at once:\n{down_out}"
    )
    assert len(icrq) == 2 and icrq[1] - call2_start < PROMPT + 1.0, (
        f"second call not placed promptly:\n{down_out}"
    )
