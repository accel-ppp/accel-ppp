import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, read_log, switch_show, wait_for, wait_up, finish_harness


@pytest.mark.l2tp_switch
def test_switch_forwards_proxy_avps(pytestconfig, accel_cmd, accel_pppd, peer_bin):
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
                    "--calling-number", "472913",
                    "--proxy-username", "simon",
                    "--proxy-password", "secretpw",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 60.0)
            assert rc == 0, err

            # The downstream placement can complete after the harness has
            # returned, so poll.
            out = ""

            def placed():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "placed: 1" in out

            wait_for(placed, 10.0)
            assert "placed: 1" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_logs_captured_proxy_authen_type_without_leaking_credentials(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The switch logs the captured Proxy-Authen-Type value at debug level and
    forwards it intact downstream. Proxy-Authen-Name and the other credential
    AVPs (RFC 2661 4.4.5) are logged by id only, never by value.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "8",
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

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "simon",
                    "--proxy-password", "secretpw",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, err

            # Log writes are queued, so the log can lag the harness exit.
            log = [""]

            def type_logged():
                log[0] = read_log(s_cfg)
                return "upstream ICCN proxy authen type = 3" in log[0]

            assert wait_for(type_logged, 5.0), (
                f"expected the decoded Proxy-Authen-Type value (3 == PAP) in the log:\n{log[0]}"
            )
            assert "captured proxy AVP Proxy-Authen-Type (id=29" in log[0], (
                f"expected a debug log line for the captured Proxy-Authen-Type AVP:\n{log[0]}"
            )
            assert "simon" not in log[0], "the proxied username leaked into the log"
            assert "secretpw" not in log[0], "the proxied password leaked into the log"
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)

    # The log only shows what the switch captured. Check what the downstream
    # harness decoded off the wire to catch corruption on re-injection.
    assert "event=recv_proxy_authen_type" in down_out, (
        f"the downstream leg's own ICCN never carried Proxy-Authen-Type at"
        f" all:\n{down_out}\n{down_err}"
    )
    assert "event=recv_proxy_authen_type" in down_out and " value=3" in down_out, (
        f"the downstream leg decoded a Proxy-Authen-Type value other than"
        f" 3 (PPP PAP) off the wire; re-injection corrupted it:\n{down_out}"
    )
