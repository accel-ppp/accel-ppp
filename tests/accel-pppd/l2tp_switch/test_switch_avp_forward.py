import re

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
                    # A harness that exits at once leaves the switch's next
                    # packet to its closed port; the ICMP error ends the
                    # upstream tunnel, and the call with it, before the ICCN
                    # is forwarded. Hold the socket until that happened.
                    "--hold-seconds", "3",
                ],
            )
            assert wait_for(
                lambda: "sending ICCN" in read_log(s_cfg), 10.0
            ), "the switch never forwarded the ICCN downstream"
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
            assert "captured AVP Proxy-Authen-Type (id=29" in log[0], (
                f"expected a debug log line for the captured Proxy-Authen-Type AVP:\n{log[0]}"
            )
            assert "simon" not in log[0], "the proxied username leaked into the log"
            assert "secretpw" not in log[0], "the proxied password leaked into the log"
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"

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


@pytest.mark.l2tp_switch
def test_switch_reinjects_every_proxy_avp_unchanged(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """All five Proxy-Authen AVPs the upstream ICCN carried come out of the
    downstream ICCN with the same bytes: none dropped, none cut short, none
    carrying another one's value (they are decoded off the wire by the
    listener, the switch's own log only shows what it captured)."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    name = "user-with-a-longer-name"
    response = "R" * 47 + "!"
    challenge_hex = "00ff10" + "a5" * 12 + "7f"
    authen_id = 42

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "6",
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
                    "--proxy-username", name,
                    "--proxy-password", response,
                    "--proxy-authen-id", str(authen_id),
                    "--proxy-challenge", challenge_hex,
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, err
            assert wait_for(lambda: "placed: 1" in switch_show(accel_cmd, switch_cli), 10.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)

    m = re.search(
        r"event=recv_proxy_avps round=0 type=(\S+) id=(\S+) name=(\S+)"
        r" challenge=(\S+) response=(\S+)",
        down_out,
    )
    assert m, f"the downstream never received an ICCN:\n{down_out}\n{down_err}"
    assert m.groups() == (
        "3",
        str(authen_id),
        name.encode().hex(),
        challenge_hex,
        response.encode().hex(),
    ), f"the downstream ICCN's Proxy-Authen AVPs differ from the upstream's:\n{down_out}"


@pytest.mark.l2tp_switch
def test_switch_forwards_an_empty_proxy_avp(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """An AVP with no value (here a Proxy-Authen-Challenge) is legal. With
    hide-avps off it has no buffer to copy; the switch must neither crash on
    it nor turn it into an absent or non-empty one downstream."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "6",
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
            l2tp_extra="hide-avps=0",
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
                    "--proxy-challenge", "",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, err
            assert wait_for(lambda: "placed: 1" in switch_show(accel_cmd, switch_cli), 10.0)
            # still serving after the empty AVP went through
            assert "[up]" in wait_up(accel_cmd, switch_cli)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)

    m = re.search(r"event=recv_proxy_avps round=0 type=3 id=-1 name=(\S+) challenge=(\S+) response=(\S+)", down_out)
    assert m, f"the downstream ICCN is missing or malformed:\n{down_out}\n{down_err}"
    assert m.group(2) == "empty", f"the empty challenge came out as {m.group(2)!r}:\n{down_out}"
    assert m.group(1) == "simon".encode().hex() and m.group(3) == "secretpw".encode().hex(), down_out
