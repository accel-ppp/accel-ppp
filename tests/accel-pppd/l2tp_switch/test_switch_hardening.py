import threading

import pytest
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports, start_instance, read_log, show_stat, switch_show, wait_up, wait_for, finish_harness,
)


@pytest.mark.l2tp_switch
def test_rule_churn_while_calls_are_matched(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """`l2tp switch add|del` runs on the CLI thread while every ICRQ/ICCN is
    matched against the same rule list on a tunnel context. Hammer the CLI
    while calls arrive: the daemon must stay alive, every call must still
    match (the untouched base rule is never removed), and the churned rules
    must all be gone afterwards.

    A stress test, mainly useful under the TSAN and ASAN legs.
    """
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
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            stop = threading.Event()
            failures = []

            def churn():
                i = 0
                while not stop.is_set():
                    value = f"9{i:05d}"
                    add = process.run([accel_cmd, "-p", str(switch_cli),
                                       f"l2tp switch add Calling-Number exact {value} downstream"])
                    if add[0] != 0:
                        failures.append(("add", value, add))
                    dele = process.run([accel_cmd, "-p", str(switch_cli),
                                        f"l2tp switch del Calling-Number exact {value}"])
                    if dele[0] != 0:
                        failures.append(("del", value, dele))
                    i += 1
                    # back-to-back accel-cmd spawns would starve the daemon
                    # on a slow runner
                    stop.wait(0.05)

            churner = threading.Thread(target=churn)
            churner.start()
            try:
                calls = 3
                for _ in range(calls):
                    peer_thread, peer_ctrl = l2tp_peer_process.start(
                        peer_bin,
                        [
                            "--peer-addr", "127.0.0.1",
                            "--peer-port", str(switch_l2tp),
                            "--secret", "upstreamsecret",
                            "--calling-number", "472913",
                        ],
                    )
                    rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 60.0)
                    assert rc == 0, err
            finally:
                stop.set()
                churner.join(120.0)

            assert not failures, failures[:3]
            assert "uptime" in show_stat(accel_cmd, switch_cli)
            # the last match can land after the harness has returned
            out = ""

            def all_matched():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return f"matched: {calls}" in out

            assert wait_for(all_matched, 10.0), out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_rapid_call_churn_leaves_no_pairing(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """Calls that end almost as soon as they start put the upstream leg's
    teardown right next to the downstream leg's placement and splice setup,
    which run on two different tunnel contexts. Whatever order the two land
    in, every pairing must be torn down again: nothing may stay "active", the
    daemon must stay responsive, and every call must still have matched.

    Like the rule-churn test, a stress test for the TSAN leg.
    """
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
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            calls = 8
            for _ in range(calls):
                peer_thread, peer_ctrl = l2tp_peer_process.start(
                    peer_bin,
                    [
                        "--peer-addr", "127.0.0.1",
                        "--peer-port", str(switch_l2tp),
                        "--secret", "upstreamsecret",
                        "--calling-number", "472913",
                        "--proxy-username", "churn",
                        "--proxy-password", "churnpw",
                        # End the call on the wire; relying on ICMP
                        # unreachable after exit is unreliable on slow
                        # runners.
                        "--send-stopccn",
                    ],
                )
                rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 90.0)
                assert rc == 0, err

            out = ""

            def drained():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "  active: 0" in out and f"matched: {calls}" in out

            wait_for(drained, 10.0)
            assert "  active: 0" in out, out
            assert f"matched: {calls}" in out, out
            assert "uptime" in show_stat(accel_cmd, switch_cli)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
