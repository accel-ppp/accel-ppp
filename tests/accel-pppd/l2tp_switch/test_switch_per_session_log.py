import os
import shutil
import tempfile

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, start_instance, switch_show, wait_for, wait_up


@pytest.mark.l2tp_switch
def test_switched_call_with_per_session_log_dir(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """A switched leg never becomes a PPP session, so it must not fire the
    per-session events: log_file would open a log file for it that nothing
    ever names or removes."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    log_dir = tempfile.mkdtemp()

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "30",
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
    [log]
    per-session-dir={log_dir}
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--hold-seconds", "5",
                ],
            )
            try:
                assert wait_for(
                    lambda: "active=1" in switch_show(accel_cmd, switch_cli, check=False),
                    8.0,
                )
                assert s_ctrl["process"].poll() is None, "the daemon died"
                assert os.listdir(log_dir) == []
            finally:
                finish_harness(thread, ctrl, 8.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
        shutil.rmtree(log_dir, ignore_errors=True)
