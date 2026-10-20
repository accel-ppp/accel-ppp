import os
import re
import subprocess
import time
from pathlib import Path

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, read_log, start_instance, switch_show, wait_for, wait_up

PATTERN = "F" * 1000
FRAMES = 2500
# 1 ms per relayed frame makes the target's tunnel context CPU-bound at about
# 1000 frames/s, as a call near the capacity of a real context is
SHIM_DELAY_MS = 1
# well above the longest wait a yielding relay may cause (one budget of
# frames plus a hop or two), well below the 2.5 s the flood lasts
BOUND_S = 1.0

_SHIM_SRC = Path(__file__).resolve().parent / "splice_delay_shim.c"


@pytest.fixture(scope="module")
def delay_shim(tmp_path_factory):
    out = tmp_path_factory.mktemp("splice_delay_shim") / "splice_delay_shim.so"
    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O1", "-Wall", "-o", str(out), str(_SHIM_SRC), "-ldl"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return str(out)


def _events(out, name):
    return [float(m.group(1)) for m in re.finditer(rf"event={name} .*?t=([0-9.]+)", out)]


def _relayed(accel_cmd, cli_port):
    """Largest bytes_in (downstream -> upstream) of any call."""
    show = switch_show(accel_cmd, cli_port, check=False)
    return max([int(v) for v in re.findall(r"bytes_in=(\d+)", show)] or [0])


def _client(switch_l2tp, number):
    return [
        "--peer-addr", "127.0.0.1",
        "--peer-port", str(switch_l2tp),
        "--secret", "upstreamsecret",
        "--calling-number", number,
        "--minimal-lcp",
        "--hold-seconds", "8",
    ]


@pytest.mark.l2tp_switch
def test_call_placed_on_a_flooded_target_is_not_starved(
    accel_cmd, accel_pppd, peer_bin, delay_shim, tmp_path
):
    """A flooded call must not hold up the other work queued on its tunnel's
    context. The target sends a burst at the switch, the shim makes relaying
    each frame cost a millisecond so the link stays busy for seconds, and a
    second call is placed on the same target meanwhile. Its ICRQ goes out only
    when the target tunnel's context runs the call queued for it, which a link
    that merely re-registers its handler keeps behind itself for as long as
    the flood lasts. The burst must still arrive whole."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    shim_log = tmp_path / "shim.log"
    asan_options = ":".join(
        filter(None, [os.environ.get("ASAN_OPTIONS"), "verify_asan_link_order=0"])
    )
    env = dict(
        os.environ,
        ASAN_OPTIONS=asan_options,
        LD_PRELOAD=delay_shim,
        SPLICE_SHIM_MARKER="FFFFFFFFFF",
        SPLICE_SHIM_DELAY_MS=str(SHIM_DELAY_MS),
        SPLICE_SHIM_LOG=str(shim_log),
        # the burst is queued at once; the kernel would drop what does not fit
        SPLICE_SHIM_RCVBUF=str(64 << 20),
    )

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--minimal-lcp",
            "--data-pattern", PATTERN,
            "--data-count", str(FRAMES),
            "--hold-seconds", "12",
        ],
    )
    clients = []
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
    match=Calling-Number,exact,472914,downstream
    """,
            thread_count=4,
            env=env,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            clients.append(l2tp_peer_process.start(peer_bin, _client(switch_l2tp, "472913")))
            assert wait_for(
                lambda: shim_log.exists() and "delay-begin" in shim_log.read_text(),
                10.0,
            ), f"the flood never reached the relay\n{read_log(s_cfg)}"
            time.sleep(0.5)

            started = time.monotonic()
            clients.append(l2tp_peer_process.start(peer_bin, _client(switch_l2tp, "472914")))

            total = FRAMES * len(PATTERN)
            wait_for(lambda: _relayed(accel_cmd, switch_cli) >= total, 30.0, interval=0.5)
            relayed = _relayed(accel_cmd, switch_cli)
        finally:
            for thread, ctrl in clients:
                finish_harness(thread, ctrl, 15.0)
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, out, err = finish_harness(down_thread, down_ctrl, 15.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{err}"

    icrqs = _events(out, "recv_icrq")
    assert len(icrqs) == 2, out + err
    waited = icrqs[1] - started
    print(f"second call reached the flooded target after {waited:.3f}s")
    assert waited < BOUND_S, (
        f"the second call reached the flooded target only after {waited:.2f}s"
        f" (the flood alone lasts {FRAMES * SHIM_DELAY_MS / 1000:.1f}s)\n{out}"
    )
    assert total <= relayed < total + len(PATTERN), (
        f"{relayed} bytes relayed, expected {total} plus the LCP frames"
    )
