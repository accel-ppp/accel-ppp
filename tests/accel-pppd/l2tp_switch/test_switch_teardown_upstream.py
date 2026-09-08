import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance


@pytest.mark.l2tp_switch
def test_upstream_tunnel_drop_tears_down_downstream(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17070, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17071,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17070,downstreamsecret
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

            # establish one switched call, then have the "MK" side itself
            # send StopCCN -- tearing down the upstream tunnel while the
            # downstream pairing is still up
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17071",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--send-stopccn",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            active = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                assert exit == 0
                if "active: 0" in out:
                    active = 0
                    break
                time.sleep(0.1)
            assert active == 0, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
