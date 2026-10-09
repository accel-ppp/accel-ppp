import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, read_log, switch_show, wait_for, wait_up


@pytest.mark.l2tp_switch
def test_switch_matches_on_proxied_username_prefix(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """Proxy-Authen-Name arrives only in ICCN, so this exercises ICCN-time
    matching in prefix mode."""
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
    # Persistent target, so its tunnel is already up when the call arrives.
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Proxy-Authen-Name,prefix,downstream-,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # Calling-number matches nothing; only the username prefix routes this call.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "000000",
                    "--proxy-username", "downstream-54546#level66@bsa-vdsl",
                    "--proxy-password", "irrelevant",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            # "placed" is counted after the downstream ICRQ is flushed, which can
            # happen after the harness exits. Poll for it.
            out = [""]

            def placed():
                out[0] = switch_show(accel_cmd, switch_cli)
                return "placed: 1" in out[0]

            assert wait_for(placed, 5.0), out[0]
            assert "matched: 1" in out[0], out[0]
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_matches_on_username_prefix_still_captures_proxy_authen_type(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """A username-prefix match, made partway through the ICCN AVP loop, must
    still capture Proxy-Authen-Type, which precedes Name on the wire."""
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
    # Persistent target, so its tunnel is already up when the call arrives.
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Proxy-Authen-Name,prefix,downstream-,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "000000",
                    "--proxy-username", "downstream-54546#level66@bsa-vdsl",
                    "--proxy-password", "irrelevant",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            # The daemon log is written from a queue, so poll instead of reading once.
            log = [""]

            def name_logged():
                log[0] = read_log(s_cfg)
                return "captured proxy AVP Proxy-Authen-Name" in log[0]

            assert wait_for(name_logged, 5.0), (
                f"sanity check failed; the match itself didn't fire:\n{log[0]}"
            )
            assert "captured proxy AVP Proxy-Authen-Type" in log[0], (
                "Proxy-Authen-Type was not captured off the upstream ICCN"
                " even though Proxy-Authen-Name was; it arrived earlier"
                " in the same ICCN, before the username-prefix match set"
                f" sess->switch_target:\n{log[0]}"
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_calling_number_takes_precedence_over_username_prefix(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """When both a Calling-Number rule and a username-prefix rule apply,
    Calling-Number wins because it is matched at ICRQ time."""
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
    # Persistent target, so its tunnel is already up when the call arrives.
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    match=Proxy-Authen-Name,prefix,downstream-,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # Both rules apply to this call: it must be counted once (matched: 1).
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "downstream-54546#level66@bsa-vdsl",
                    "--proxy-password", "irrelevant",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            (exit, out, err) = process.run([accel_cmd, "-p", str(switch_cli), "l2tp switch show"])
            assert "matched: 1" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
