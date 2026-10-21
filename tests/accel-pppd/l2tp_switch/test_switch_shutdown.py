import re
import signal
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process, process
from helpers import (
    alloc_ports,
    EXIT_WAIT,
    finish_harness,
    read_log,
    start_instance,
    switch_show,
    wait_exit,
    WAIT_FACTOR,
    wait_for,
    wait_up,
)


# How long after the ICCN the downstream ends the call in the soft-shutdown
# test: the checks between the call coming up and the CDN take well under a
# second natively, so this is stretched with L2TP_TEST_TIMEOUT_FACTOR for slow
# (emulated, sanitized) runs instead of racing them.
CDN_AFTER_ICCN_MS = int(5000 * max(1.0, WAIT_FACTOR / 6))


def _start_switch(accel_pppd, accel_cmd, switch_cli, switch_l2tp, down_l2tp):
    return start_instance(
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


def _start_call(peer_bin, switch_l2tp):
    return l2tp_peer_process.start(
        peer_bin,
        [
            "--peer-addr", "127.0.0.1",
            "--peer-port", str(switch_l2tp),
            "--secret", "upstreamsecret",
            "--calling-number", "472913",
            "--wait-cdn",
        ],
    )


def _wait_one_active(accel_cmd, switch_cli):
    return wait_for(lambda: "active=1" in switch_show(accel_cmd, switch_cli), 5.0)


def _wait_exit(ctrl, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ctrl["process"].poll() is not None:
            return True
        time.sleep(0.05)
    return False


@pytest.mark.l2tp_switch
def test_soft_shutdown_waits_for_switched_calls(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """`shutdown soft` ends once the last call is gone. A switched call has no
    ap_session, so the core has to be told about it."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    # The downstream ends the call a while after the ICCN.
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--cdn-after-iccn-ms", str(CDN_AFTER_ICCN_MS),
            "--hold-seconds", "30",
        ],
    )

    try:
        s_started, s_thread, s_ctrl, s_cfg = _start_switch(
            accel_pppd, accel_cmd, switch_cli, switch_l2tp, down_l2tp
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = _start_call(peer_bin, switch_l2tp)
            try:
                assert _wait_one_active(accel_cmd, switch_cli)

                process.run([accel_cmd, "-p", str(switch_cli), "shutdown soft"])

                # negative check: the daemon stays up for a good part of the
                # time the call has left, whatever the speed of the host
                assert not _wait_exit(s_ctrl, CDN_AFTER_ICCN_MS / 1000 * 0.4), (
                    "exited with a call up"
                )
                assert "active=1" in switch_show(accel_cmd, switch_cli)

                # the call ends by itself, then the daemon follows
                assert wait_exit(
                    s_ctrl,
                    CDN_AFTER_ICCN_MS / 1000 + EXIT_WAIT,
                    accel_cmd,
                    switch_cli,
                ), "did not exit after the call ended"
            finally:
                finish_harness(thread, ctrl, 5.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)


def _signal_term(accel_cmd, switch_cli, s_ctrl):
    s_ctrl["process"].send_signal(signal.SIGTERM)


def _cli_shutdown_hard(accel_cmd, switch_cli, s_ctrl):
    process.run([accel_cmd, "-p", str(switch_cli), "shutdown hard"])


@pytest.mark.l2tp_switch
@pytest.mark.parametrize("trigger", [_signal_term, _cli_shutdown_hard], ids=["sigterm", "shutdown-hard"])
def test_sigterm_ends_switched_calls(pytestconfig, accel_cmd, accel_pppd, peer_bin, trigger):
    """SIGTERM (or `shutdown hard`) asks every call to end and exits once they
    have: the upstream leg gets a CDN with the administrative result code, and
    the downstream leg is told the same one."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "20",
        ],
    )

    try:
        s_started, s_thread, s_ctrl, s_cfg = _start_switch(
            accel_pppd, accel_cmd, switch_cli, switch_l2tp, down_l2tp
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = _start_call(peer_bin, switch_l2tp)
            try:
                assert _wait_one_active(accel_cmd, switch_cli)

                trigger(accel_cmd, switch_cli, s_ctrl)

                rc, out, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
                assert rc == 0, err
                m = re.search(r"event=got_cdn type=cdn res=(\d+) err=(\d+)", out)
                assert m, out
                assert (m.group(1), m.group(2)) == ("3", "0"), out

                assert wait_exit(s_ctrl, EXIT_WAIT, accel_cmd, switch_cli), (
                    "did not exit after the calls ended"
                )
            finally:
                finish_harness(thread, ctrl, 5.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 8.0)

    # the leg that did not get the shutdown is told why the call ended
    m = re.search(r"event=recv_cdn round=0 t=[\d.]+ res=(\d+) err=(\d+)", down_out)
    assert m, down_out
    assert (m.group(1), m.group(2)) == ("3", "0"), down_out


@pytest.mark.l2tp_switch
def test_soft_shutdown_rejects_icrq_matched_call_at_iccn(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """A call matched at the ICRQ and still waiting for its ICCN when
    `shutdown soft` is issued is not bridged once the ICCN arrives: it gets
    the administrative CDN, like a call first matched at the ICCN. Calls that
    are already established are not touched (see the test above).

    This covers the soft-shutdown case; the narrow race where the match joins
    the call list after the SIGTERM walk is closed by the same flag check
    under the list lock and is not exercised here.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "30",
        ],
    )

    try:
        s_started, s_thread, s_ctrl, s_cfg = _start_switch(
            accel_pppd, accel_cmd, switch_cli, switch_l2tp, down_l2tp
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # the ICCN follows the ICRP after 3 s
            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--iccn-delay-ms", "3000",
                    "--wait-cdn",
                ],
            )
            try:
                assert wait_for(
                    lambda: "call matches l2tp-switch target" in read_log(s_cfg),
                    5.0,
                ), "ICRQ was not matched"

                process.run([accel_cmd, "-p", str(switch_cli), "shutdown soft"])

                rc, out, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
                assert rc == 0, err
                m = re.search(r"event=got_cdn type=cdn res=(\d+) err=(\d+)", out)
                assert m, out
                assert (m.group(1), m.group(2)) == ("3", "0"), out

                assert wait_exit(s_ctrl, EXIT_WAIT, accel_cmd, switch_cli), (
                    "did not exit after the call ended"
                )
            finally:
                finish_harness(thread, ctrl, 5.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
