"""A call placed on a target tunnel that the peer's StopCCN closes first.

A call that arrives while the target tunnel is established queues its
placement on that tunnel's context. If the peer's StopCCN is read before the
queued placement runs, the placement finds a closing tunnel. An on-demand
target hands the call back (it takes the next tunnel); a persistent target has
nowhere to put it and disconnects the call with the general error 2/6.

The window is the time the tunnel's context is busy. A first call ends and the
CDN to the downstream is held back by a shim, which blocks that context for
CDN_DELAY_MS. In that time a second call arrives (the tunnel still looks
established, its placement is queued) and the downstream sends its StopCCN.
"""

import os
import re
import subprocess
import time
from pathlib import Path

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, read_log, start_instance, wait_up

CDN_DELAY_MS = 3000
# After the downstream's ICCN. The first call hangs up about half a second
# later, which starts the block; the second call is placed at about 1.5 s; the
# StopCCN lands in the middle of the block.
STOPCCN_AFTER_ICCN_MS = 2500
CALL2_AFTER_CALL1 = 0.5

_SHIM_SRC = Path(__file__).resolve().parent / "cdn_delay_shim.c"


@pytest.fixture(scope="module")
def cdn_delay_shim(tmp_path_factory):
    out = tmp_path_factory.mktemp("cdn_delay_shim") / "cdn_delay_shim.so"
    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O1", "-Wall", "-o", str(out), str(_SHIM_SRC), "-ldl"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return str(out)


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


def _run(accel_cmd, accel_pppd, peer_bin, shim, mode):
    """Runs the scenario against a target of `mode`; returns the second
    call's output, the downstream's, and the switch's log."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    asan_options = ":".join(
        filter(None, [os.environ.get("ASAN_OPTIONS"), "verify_asan_link_order=0"])
    )
    env = dict(
        os.environ,
        ASAN_OPTIONS=asan_options,
        LD_PRELOAD=shim,
        CDN_SHIM_PORT=str(down_l2tp),
        CDN_SHIM_DELAY_MS=str(CDN_DELAY_MS),
    )
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "2",
            "--hold-seconds", "40",
            "--stopccn-after-iccn-ms", str(STOPCCN_AFTER_ICCN_MS),
        ],
    )
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd, accel_cmd, switch_cli, "127.0.0.1", switch_l2tp, "upstreamsecret",
        # several workers, so the blocked tunnel context does not stall the rest
        thread_count=4,
        env=env,
        extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,{mode}
    idle-linger=60
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    call2_out = ""
    try:
        if mode == "persistent":
            assert "[up]" in wait_up(accel_cmd, switch_cli)
        t1, c1 = _call(peer_bin, switch_l2tp, ["--data-pattern", "SWITCHOK", "--send-stopccn"])
        rc, out, err = l2tp_peer_process.wait(t1, c1, 30.0)
        assert rc == 0, f"first call failed (rc={rc}): {err}\n{out}"
        time.sleep(CALL2_AFTER_CALL1)

        # the block ends 3 s after it began, a disconnect follows at once
        t2, c2 = _call(peer_bin, switch_l2tp, ["--wait-cdn", "--cdn-timeout", "7"])
        _, call2_out, _ = l2tp_peer_process.wait(t2, c2, 30.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        switch_log = read_log(s_cfg)
        config.delete_tmp(s_cfg)
        _, down_out, down_err = finish_harness(down_thread, down_ctrl, 5.0)

    return call2_out, down_out + "\n" + down_err, switch_log


@pytest.mark.l2tp_switch
def test_call_placed_on_a_tunnel_the_peer_stopccn_closed_is_requeued(
    pytestconfig, accel_cmd, accel_pppd, peer_bin, cdn_delay_shim
):
    call2_out, down_out, switch_log = _run(accel_cmd, accel_pppd, peer_bin, cdn_delay_shim, "on-demand")

    context = f"\n{call2_out}\n{down_out}\n{switch_log}"
    assert "event=sent_late_stopccn" in down_out, f"the downstream never sent its StopCCN:{context}"
    assert "target tunnel closed under the call, waiting for a new one" in switch_log, (
        f"the call's placement did not find the closed tunnel:{context}"
    )
    assert "event=got_cdn" not in call2_out, (
        f"the call placed on the closed tunnel was disconnected:{context}"
    )
    assert _count(down_out, "recv_sccrq") == 2, f"no second tunnel for the call:{context}"
    assert _count(down_out, "recv_icrq") == 2, f"the call never reached the downstream:{context}"


@pytest.mark.l2tp_switch
def test_persistent_target_call_on_a_closed_tunnel_gets_the_general_error(
    pytestconfig, accel_cmd, accel_pppd, peer_bin, cdn_delay_shim
):
    call2_out, down_out, switch_log = _run(accel_cmd, accel_pppd, peer_bin, cdn_delay_shim, "persistent")

    context = f"\n{call2_out}\n{down_out}\n{switch_log}"
    assert "event=sent_late_stopccn" in down_out, f"the downstream never sent its StopCCN:{context}"
    assert "target tunnel not available, disconnecting upstream call" in switch_log, context
    m = re.search(r"event=got_cdn type=(\w+) res=(\d+) err=(\d+)", call2_out)
    assert m, f"the call was not disconnected:{context}"
    assert m.groups() == ("cdn", "2", "6"), context
