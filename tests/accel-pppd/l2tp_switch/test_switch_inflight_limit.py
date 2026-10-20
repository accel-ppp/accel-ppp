import re

import pytest
from common import accel_pppd_process, config, l2tp_peer_process
from helpers import (
    alloc_ports,
    finish_harness,
    read_log,
    start_instance,
    switch_show,
    wait_for,
    wait_up,
)

# L2TP_SWITCH_INFLIGHT_MAX in l2tp.c
LIMIT = 64
# the first calls end themselves this long after their ICCN, long enough to
# check the limit first
SHORT_CALL_MS = 10000
SHORT_CALLS = 2


def _call(peer_bin, switch_l2tp, extra):
    return l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(switch_l2tp),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
        ] + extra,
    )


def _counter(accel_cmd, cli_port, name):
    out = switch_show(accel_cmd, cli_port, check=False)
    m = re.search(rf"^\s*{name}: (\d+)\r?$", out, re.M)
    return int(m.group(1)) if m else -1


@pytest.mark.l2tp_switch
def test_unanswered_calls_on_an_established_target_are_limited(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The downstream LNS never answers an ICRQ. Calls placed on its
    established tunnel bypass the pending queue and the receive window, so only
    a limit on the calls awaiting an answer keeps the send queue from growing
    without bound. The surplus is refused, the first calls stay pending, and
    a slot is free again when one of them ends."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--no-icrp",
            "--hold-seconds", "90",
        ],
    )
    calls = []

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
    target=silent,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,silent
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            for i in range(LIMIT):
                extra = ["--hold-seconds", "60"]
                if i < SHORT_CALLS:
                    extra += [
                        "--send-cdn", "3:0",
                        "--send-cdn-delay-ms", str(SHORT_CALL_MS),
                    ]
                calls.append(_call(peer_bin, switch_l2tp, extra))

            assert wait_for(
                lambda: _counter(accel_cmd, switch_cli, "placed") == LIMIT, 40.0
            ), switch_show(accel_cmd, switch_cli) + read_log(s_cfg)

            # over the limit: refused, however many ask
            for _ in range(3):
                thread, ctrl = _call(peer_bin, switch_l2tp, ["--wait-cdn"])
                rc, _, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
                assert rc == 0, err

            out = switch_show(accel_cmd, switch_cli)
            assert _counter(accel_cmd, switch_cli, "refused") == 3, out
            assert _counter(accel_cmd, switch_cli, "placed") == LIMIT, out
            assert "awaiting an answer" in read_log(s_cfg)

            # the first calls ending frees slots
            def slot_free():
                thread, ctrl = _call(peer_bin, switch_l2tp, ["--hold-seconds", "20"])
                calls.append((thread, ctrl))
                return wait_for(
                    lambda: _counter(accel_cmd, switch_cli, "placed") > LIMIT, 3.0
                )

            assert wait_for(slot_free, SHORT_CALL_MS / 1000.0 + 20.0, interval=1.0), (
                switch_show(accel_cmd, switch_cli) + read_log(s_cfg)
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        for thread, ctrl in calls:
            finish_harness(thread, ctrl, 0.1)
        finish_harness(down_thread, down_ctrl, 5.0)
