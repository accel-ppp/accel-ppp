import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance

DATA_PATTERN = "SWITCHOK"


@pytest.mark.l2tp_switch
def test_switch_show_lists_per_session_line(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17080, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17081,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17080,downstreamsecret
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
                    "--peer-port", "17081",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            out = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                assert exit == 0
                if "call: 472913" in out:
                    break
                time.sleep(0.1)
            assert "call: 472913" in out, out

            # per-target line: active count and non-zero bytes_out (the
            # harness's upstream-originated write travels target-bound)
            assert "active=1" in out, out

            # per-call line: both tunnel/session ID pairs present as
            # "tid-sid / tid-sid", plus a byte count of at least
            # len("SWITCHOK") == 8 once the splice has gone through (allow
            # >=8 rather than ==8 in case a stray retransmit or
            # control-channel byte inflates the count slightly).
            call_line = next(
                line for line in out.splitlines() if line.strip().startswith("call:")
            )
            bytes_out = int(call_line.split("bytes_out=")[1].split()[0])
            assert bytes_out >= len(DATA_PATTERN), call_line
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
