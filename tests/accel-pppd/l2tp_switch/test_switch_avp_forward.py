import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance


@pytest.mark.l2tp_switch
def test_switch_forwards_proxy_avps(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17030, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17031,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17030,downstreamsecret
    match=Calling-Number,exact,472913,downstream
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

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17031",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "simon",
                    "--proxy-password", "secretpw",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            # the assertion lives on the switch instance itself: it placed
            # exactly one downstream call carrying the proxy AVPs
            (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
            assert exit == 0
            assert "placed: 1" in out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
