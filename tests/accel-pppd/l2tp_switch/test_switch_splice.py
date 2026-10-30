import pytest
import subprocess
import time
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, wait_up

DATA_PATTERN = "SWITCHOK"


@pytest.mark.l2tp_switch
def test_switch_splices_data_plane(pytestconfig, accel_cmd, accel_pppd, peer_bin):
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

            capture = subprocess.Popen(
                ["tcpdump", "-l", "-A", "-i", "lo", "udp", "port", str(down_l2tp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(0.5)  # let tcpdump attach before traffic starts

            try:
                peer_thread, peer_ctrl = l2tp_peer_process.start(
                    peer_bin,
                    [
                        "--peer-addr", "127.0.0.1",
                        "--peer-port", str(switch_l2tp),
                        "--secret", "upstreamsecret",
                        "--calling-number", "472913",
                        "--data-pattern", DATA_PATTERN,
                    ],
                )
                rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
                assert rc == 0, err

                time.sleep(0.5)  # let the capture see the data packet
            finally:
                capture.terminate()
                capture_out, _ = capture.communicate(timeout=5.0)

            assert DATA_PATTERN in capture_out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
