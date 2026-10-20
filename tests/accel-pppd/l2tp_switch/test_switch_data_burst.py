import re

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, start_instance, wait_up


def _relay(accel_pppd, accel_cmd, peer_bin, pattern, count):
    """Sends `count` frames of `pattern` through a switch and returns what
    the downstream peer received: (frames, bytes, longest)."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--minimal-lcp",
            "--count-data",
            "--rcvbuf", "16777216",
            "--data-pattern", pattern,
            "--hold-seconds", "30",
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

            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", pattern,
                    "--data-count", str(count),
                    "--hold-seconds", "1",
                ],
            )
            rc, out, err = finish_harness(thread, ctrl, 20.0)
            assert rc == 0, err
            assert f"event=data_sent frames={count}" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        _, out, _ = finish_harness(down_thread, down_ctrl, 8.0)

    m = re.search(r"event=data_rx round=\d+ frames=(\d+) bytes=(\d+) longest=(\d+)", out)
    assert m, out
    return tuple(int(x) for x in m.groups())


@pytest.mark.l2tp_switch
def test_burst_of_frames_is_relayed_completely(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """A busy call yields after a fixed number of frames. The read handler is
    edge-triggered, so a yield that does not get the socket reported again
    would strand the frames still queued behind it."""
    count = 3000
    frames, size, _ = _relay(accel_pppd, accel_cmd, peer_bin, "A" * 100, count)

    assert frames == count
    assert size == count * 100


@pytest.mark.l2tp_switch
def test_frames_larger_than_a_page_stay_whole(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """Before Linux 6.5 splice() cuts a datagram bigger than a page into one
    per page, so such a frame has to go out with write()."""
    frames, size, longest = _relay(accel_pppd, accel_cmd, peer_bin, "A" * 6000, 3)

    assert frames == 3
    assert longest == 6000
    assert size == 3 * 6000
