"""on-demand targets: a call arriving as the idle linger closes the tunnel.

The idle-linger close and a new call's placement are queued on the same
tunnel context in arrival order. A call that arrives after the linger timer
has fired, but before the close has run, finds the tunnel established and
queues its placement behind the close. The close then sends StopCCN and the
placement finds a closing tunnel; the call must go to a new tunnel instead of
being disconnected.

The window is the time the tunnel's context needs to get to its queued work,
so the downstream peer keeps that context busy with junk for a few seconds
spanning the expiry (--fin-flood without the StopCCN).
"""

import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, read_log, start_instance, switch_show, wait_for

# Must match idle-linger= below.
IDLE_LINGER = 4
# The junk starts before the linger expires and ends well after the second
# call is placed, both relative to the first call's CDN reaching the peer.
FLOOD_START_MS = 3500
FLOOD_LEN_MS = 3500
# The second call goes in after the expiry, inside the flood.
CALL2_AFTER_END = IDLE_LINGER + 0.6


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


def _count(out, name):
    return len(re.findall(rf"event={name} round=\d+ ", out))


@pytest.mark.l2tp_switch
def test_call_arriving_after_idle_expiry_is_not_disconnected(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "2",
            "--hold-seconds", "40",
            "--fin-flood", f"0:{FLOOD_START_MS}:{FLOOD_LEN_MS}",
            "--fin-flood-on", "cdn",
            "--fin-flood-no-stopccn",
        ],
    )
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd, accel_cmd, switch_cli, "127.0.0.1", switch_l2tp, "upstreamsecret",
        # several workers, so the flooded tunnel does not stall the timers
        thread_count=4,
        extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    idle-linger={IDLE_LINGER}
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    call2_out = ""
    try:
        t1, c1 = _call(peer_bin, switch_l2tp, ["--data-pattern", "SWITCHOK", "--send-stopccn"])
        rc, out, err = l2tp_peer_process.wait(t1, c1, 30.0)
        assert rc == 0, f"first call failed (rc={rc}): {err}\n{out}"
        assert wait_for(lambda: "active: 0" in switch_show(accel_cmd, switch_cli), 15.0)
        ended = time.monotonic()

        time.sleep(max(0.0, ended + CALL2_AFTER_END - time.monotonic()))
        t2, c2 = _call(peer_bin, switch_l2tp, ["--wait-cdn", "--cdn-timeout", "5"])
        # Healthy: no CDN, so it ends by its own timeout.
        _, call2_out, _ = l2tp_peer_process.wait(t2, c2, 20.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        switch_log = read_log(s_cfg)
        config.delete_tmp(s_cfg)
        down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 5.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

    context = f"\n{call2_out}\n{down_out}\n{down_err}\n{switch_log}"
    assert "event=fin_flood_start" in down_out, f"the downstream never flooded:{context}"
    assert "event=got_cdn" not in call2_out, (
        f"the call arriving after the idle expiry was disconnected:{context}"
    )
    assert _count(down_out, "recv_sccrq") == 2, f"no second tunnel for the call:{context}"
    assert _count(down_out, "recv_icrq") == 2, f"the call never reached the downstream:{context}"
