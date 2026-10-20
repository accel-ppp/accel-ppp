import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, read_log, start_instance, wait_for, wait_up


@pytest.mark.l2tp_switch
def test_long_proxy_avp_survives_hiding(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """With hide-avps the value gets 16 to 143 bytes of padding. The AVP
    length field is 10 bits, so a long proxied value used to come out as a
    corrupt downstream ICCN. The padding has to shrink to fit."""
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
            l2tp_extra="hide-avps=1",
            extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # 950 bytes fit an AVP, but not with the longest padding
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "u" * 950,
                    "--proxy-password", "secretpw",
                    "--hold-seconds", "5",
                ],
            )
            try:
                def downstream_got_iccn():
                    return "handling ICCN" in read_log(d_cfg)

                assert wait_for(downstream_got_iccn, 6.0), read_log(d_cfg)[-3000:]
                assert "incorrect hidden avp" not in read_log(d_cfg)
            finally:
                finish_harness(peer_thread, peer_ctrl, 8.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
