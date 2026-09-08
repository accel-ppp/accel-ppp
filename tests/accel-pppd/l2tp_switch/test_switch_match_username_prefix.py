import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance


@pytest.mark.l2tp_switch
def test_switch_matches_on_proxied_username_prefix(pytestconfig, accel_cmd, accel_pppd):
    """Proxy-Authen-Name only arrives in ICCN, not ICRQ (unlike
    Calling-Number/Called-Number) -- this exercises the switch's other
    matching pass, run from within l2tp_recv_ICCN's own AVP loop, and its
    prefix mode rather than exact.
    """
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17110, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17111,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17110,downstreamsecret
    match=Proxy-Authen-Name,prefix,downstream-,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            # calling-number deliberately does NOT match anything -- only
            # the proxied username's prefix should route this call.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17111",
                    "--secret", "upstreamsecret",
                    "--calling-number", "000000",
                    "--proxy-username", "downstream-54546#level66@bsa-vdsl",
                    "--proxy-password", "irrelevant",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
            assert "matched: 1" in out, out
            assert "placed: 1" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_calling_number_takes_precedence_over_username_prefix(
    pytestconfig, accel_cmd, accel_pppd
):
    """When both an exact Calling-Number rule and a username-prefix rule
    could apply, Calling-Number wins -- it's checked at ICRQ time, before
    Proxy-Authen-Name is even available (ICCN-time matching only runs at
    all if sess->switch_target is still unset)."""
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17112, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17113,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17112,downstreamsecret
    match=Calling-Number,exact,472913,downstream
    match=Proxy-Authen-Name,prefix,downstream-,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            # both rules could apply to this one call -- proves this
            # doesn't double-count (matched: 1, not 2) and doesn't crash
            # attempting to re-match an already-tagged session.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17113",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "downstream-54546#level66@bsa-vdsl",
                    "--proxy-password", "irrelevant",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
            assert "matched: 1" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
