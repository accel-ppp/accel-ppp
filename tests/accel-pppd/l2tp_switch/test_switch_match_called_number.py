import pytest
import time
from common import process, l2tp_peer_process
from helpers import start_instance


@pytest.mark.l2tp_switch
def test_switch_matches_on_called_number(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17022, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17023,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17022,downstreamsecret
    match=Called-Number,exact,5551234,downstream
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
                    "--peer-port", "17023",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",  # deliberately not the match key
                    "--called-number", "5551234",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
            assert "matched: 1" in out
        finally:
            from common import accel_pppd_process, config
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        from common import accel_pppd_process, config
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
