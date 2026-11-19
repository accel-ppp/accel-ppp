import re
import threading

import pytest
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports, fd_count, fd_targets, finish_harness, l2tp_finishing, read_log,
    show_stat, start_instance, switch_show, wait_for, wait_up,
)


# Rounds of `l2tp switch add` + `del` the churner must have completed while the
# calls were being matched, so the churn demonstrably overlapped them. How many
# calls that takes depends on how fast the runner is (a round is two accel-cmd
# spawns), so calls are placed until both counts are reached.
MIN_CHURN_ITERATIONS = 3
MIN_CALLS = 3
MAX_CALLS = 40


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
            iterations = []
            base_rule = "Calling-Number exact 472913 -> downstream"

            def cli(command):
                """The reply text is what tells whether the command worked:
                accel-cmd exits 0 either way. A CLI that cannot be reached
                at all shows up as an exception."""
                try:
                    rc, out, err = process.run(
                        [accel_cmd, "-p", str(switch_cli), command])
                except Exception as e:  # recorded: the thread must not die
                    failures.append((command, repr(e)))
                    return ""
                reply = out + err
                if rc != 0 or "failed" in reply:
                    failures.append((command, rc, reply))
                return reply

            def churn():
                i = 0
                while not stop.is_set():
                    value = f"9{i:05d}"
                    cli(f"l2tp switch add Calling-Number exact {value} downstream")
                    cli(f"l2tp switch del Calling-Number exact {value}")
                    i += 1
                    iterations.append(i)
                    # back-to-back accel-cmd spawns would starve the daemon
                    # on a slow runner
                    stop.wait(0.05)

            churner = threading.Thread(target=churn)
            churner.start()
            try:
                # the churn is running before the first call is matched
                assert wait_for(lambda: len(iterations) >= 1, 30.0), (
                    f"the churner never completed a round: {failures[:3]}"
                )
                calls = 0
                rounds_at_start = len(iterations)
                while calls < MIN_CALLS or (
                    len(iterations) - rounds_at_start < MIN_CHURN_ITERATIONS
                    and calls < MAX_CALLS
                ):
                    calls += 1
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

            assert not churner.is_alive(), "the churner thread never finished"
            assert not failures, failures[:3]
            assert len(iterations) - rounds_at_start >= MIN_CHURN_ITERATIONS, (
                f"only {len(iterations) - rounds_at_start} add/del rounds ran"
                f" during {calls}"
                " calls: the rule list was not churned while calls matched"
            )
            # no churned rule may be left behind, and the base rule is intact
            rules = switch_show(accel_cmd, switch_cli).split("rules:")[1].split("calls:")[0]
            assert base_rule in rules, rules
            assert len(rules.strip().splitlines()) == 1, rules
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


def _call_args(switch_l2tp, *extra):
    return [
        "--peer-addr", "127.0.0.1",
        "--peer-port", str(switch_l2tp),
        "--secret", "upstreamsecret",
        "--calling-number", "472913",
        *extra,
    ]


def _switch_calls(accel_cmd, switch_cli):
    """The `calls:` counters of `l2tp switch show` as a dict."""
    out = switch_show(accel_cmd, switch_cli)
    return {
        name: int(value)
        for name, value in re.findall(r"^  (matched|placed|connected|active): (\d+)\r?$", out, re.M)
    }


@pytest.mark.l2tp_switch
def test_rapid_call_churn_leaves_no_pairing(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """Calls that end almost as soon as they start put the upstream leg's
    teardown right next to the downstream leg's placement and splice setup,
    which run on two different tunnel contexts. Whatever order the two land
    in, every pairing must be torn down again: nothing may stay "active", no
    session, tunnel or descriptor may be left behind, the daemon must stay
    responsive, and every call must still have matched.

    The downstream is the peer harness behind a persistent target, not an
    accel LNS: that one StopCCNs when its last session ends, so no pairing
    would ever form on a tunnel that is gone by the time the next call comes.

    Like the rule-churn test, a stress test for the TSAN leg.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    # One tunnel for all calls (the harness serves a tunnel until its hold
    # time is up), and it ends each call itself soon after its ICCN, so both
    # legs tear down around each other.
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--cdn-after-iccn-ms", "300",
            "--hold-seconds", "120",
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
            # upstream tunnels that ended with a StopCCN are gone after 3s, not 31s
            l2tp_extra="""rtimeout=1
    retransmit=2
    rtimeout-cap=2""",
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)
            pid = s_ctrl["process"].pid

            def settled():
                return (
                    l2tp_finishing(accel_cmd, switch_cli) == (0, 0)
                    and _switch_calls(accel_cmd, switch_cli)["active"] == 0
                )

            # A call that really pairs, to know it can and to take the
            # baseline descriptor count of a persistent tunnel in use.
            rc, out, err = l2tp_peer_process.wait(
                *l2tp_peer_process.start(peer_bin, _call_args(switch_l2tp, "--wait-cdn")),
                20.0,
            )
            assert rc == 0, err
            assert wait_for(settled, 20.0), switch_show(accel_cmd, switch_cli)
            calls = _switch_calls(accel_cmd, switch_cli)
            assert calls["placed"] == 1 and calls["connected"] == 1, calls
            baseline_fds = fd_count(pid, switch_cli)

            churned = 8
            for _ in range(churned):
                rc, out, err = l2tp_peer_process.wait(
                    *l2tp_peer_process.start(
                        peer_bin,
                        _call_args(
                            switch_l2tp,
                            "--proxy-username", "churn",
                            "--proxy-password", "churnpw",
                            # End the call on the wire; relying on ICMP
                            # unreachable after exit is unreliable on slow
                            # runners.
                            "--send-stopccn",
                        ),
                    ),
                    90.0,
                )
                assert rc == 0, err

            total = churned + 1
            assert wait_for(settled, 30.0), (
                switch_show(accel_cmd, switch_cli)
                + f"\nfinishing (tunnels, sessions): {l2tp_finishing(accel_cmd, switch_cli)}"
                + "\n" + read_log(s_cfg)
            )
            calls = _switch_calls(accel_cmd, switch_cli)
            assert calls["matched"] == total, calls
            assert 1 <= calls["connected"] <= calls["placed"] <= total, calls
            assert calls["active"] == 0, calls
            assert "active=0" in switch_show(accel_cmd, switch_cli)
            assert wait_for(lambda: fd_count(pid, switch_cli) <= baseline_fds, 10.0), (
                f"{fd_count(pid, switch_cli)} file descriptors open, baseline"
                f" {baseline_fds}:\n" + "\n".join(fd_targets(pid))
            )
            assert "[up]" in switch_show(accel_cmd, switch_cli)
            assert "uptime" in show_stat(accel_cmd, switch_cli)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
