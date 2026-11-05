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
# the last calls end themselves this long after their ICCN, long enough to
# check the limit first; they are started once the others are placed, so a
# slow host cannot spend the time placing calls
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


def _long_call_args():
    return ["--hold-seconds", "60"]


def _short_call_args():
    return _long_call_args() + [
        "--send-cdn", "3:0",
        "--send-cdn-delay-ms", str(SHORT_CALL_MS),
    ]


def _start_call(peer_bin, switch_l2tp, calls, extras, extra):
    calls.append(_call(peer_bin, switch_l2tp, extra))
    extras.append(extra)


def _replace_failed_calls(peer_bin, switch_l2tp, calls, extras):
    """Starts a call in place of every one whose harness gave up before it
    was placed (the call lost its SCCRQ or its reply, which a slow emulated
    host does when it starts dozens of processes at once), with the same
    arguments. The harnesses hold their calls for far longer than this test
    runs, so one that has exited never reached the switch's counters."""
    for i, (thread, ctrl) in enumerate(calls):
        if thread.is_alive() or ctrl["process"].returncode in (None, 0):
            continue
        print(f"call {i} failed (rc={ctrl['process'].returncode}), starting"
              f" another: {ctrl['err']}", flush=True)
        calls[i] = _call(peer_bin, switch_l2tp, extras[i])


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
    extras = []

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

            def placed():
                _replace_failed_calls(peer_bin, switch_l2tp, calls, extras)
                return _counter(accel_cmd, switch_cli, "placed")

            for _ in range(LIMIT - SHORT_CALLS):
                _start_call(peer_bin, switch_l2tp, calls, extras,
                            _long_call_args())
            assert wait_for(
                lambda: placed() == LIMIT - SHORT_CALLS, 60.0, interval=0.5
            ), switch_show(accel_cmd, switch_cli) + read_log(s_cfg)

            for _ in range(SHORT_CALLS):
                _start_call(peer_bin, switch_l2tp, calls, extras,
                            _short_call_args())
            assert wait_for(lambda: placed() == LIMIT, 60.0, interval=0.5), (
                switch_show(accel_cmd, switch_cli) + read_log(s_cfg)
            )

            # over the limit: refused, however many ask
            for _ in range(3):
                thread, ctrl = _call(peer_bin, switch_l2tp, ["--wait-cdn"])
                rc, _, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
                assert rc == 0, err

            out = switch_show(accel_cmd, switch_cli)
            assert _counter(accel_cmd, switch_cli, "refused") == 3, out
            assert _counter(accel_cmd, switch_cli, "placed") == LIMIT, out
            assert "awaiting an answer" in read_log(s_cfg)

            # the short calls ending free slots
            def slot_free():
                _start_call(peer_bin, switch_l2tp, calls, extras,
                            ["--hold-seconds", "20"])
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


# the downstream LNS answers the SCCRQ this late, long enough for every call
# to be queued and hang up first even on a slow host
SLOW_SCCRP_MS = 40000
HANG_UP_MS = 1000


@pytest.mark.l2tp_switch
def test_calls_that_hang_up_while_queued_do_not_keep_their_slots(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """LIMIT calls queue for an on-demand tunnel that is slow to connect and
    hang up before it is up. The drain finds them closed; they must not keep
    the slot the drain takes for them, or the target refuses the next call
    although nothing is waiting for an answer."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--sccrp-delay-ms", str(SLOW_SCCRP_MS),
            "--no-icrp",
            "--hold-seconds", "120",
        ],
    )
    calls = []
    extras = []

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
    target=slow,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,slow
    connect-timeout=100
    """,
        )
        assert s_started

        try:
            hang_up = ["--hold-seconds", "60",
                       "--send-cdn", "3:0",
                       "--send-cdn-delay-ms", str(HANG_UP_MS)]
            for _ in range(LIMIT):
                _start_call(peer_bin, switch_l2tp, calls, extras, hang_up)

            def all_queued_and_gone():
                _replace_failed_calls(peer_bin, switch_l2tp, calls, extras)
                out = switch_show(accel_cmd, switch_cli, check=False)
                return (_counter(accel_cmd, switch_cli, "matched") >= LIMIT
                        and _counter(accel_cmd, switch_cli, "active") == 0
                        and "[connecting]" in out)

            assert wait_for(all_queued_and_gone, 60.0, interval=0.5), (
                "the calls were not all queued and hung up before the tunnel"
                " came up\n" + switch_show(accel_cmd, switch_cli)
                + read_log(s_cfg)
            )

            # the tunnel comes up, the drain finds every call closed
            assert wait_for(
                lambda: "[idle]" in switch_show(accel_cmd, switch_cli, check=False),
                SLOW_SCCRP_MS / 1000.0 + 20.0, interval=1.0,
            ), switch_show(accel_cmd, switch_cli) + read_log(s_cfg)
            assert _counter(accel_cmd, switch_cli, "placed") == 0

            _start_call(peer_bin, switch_l2tp, calls, extras,
                        ["--hold-seconds", "20"])
            assert wait_for(
                lambda: _counter(accel_cmd, switch_cli, "placed") == 1, 15.0,
                interval=0.5,
            ), switch_show(accel_cmd, switch_cli) + read_log(s_cfg)
            out = switch_show(accel_cmd, switch_cli)
            assert _counter(accel_cmd, switch_cli, "refused") == 0, out
            assert "awaiting an answer" not in read_log(s_cfg)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        for thread, ctrl in calls:
            finish_harness(thread, ctrl, 0.1)
        finish_harness(down_thread, down_ctrl, 5.0)
