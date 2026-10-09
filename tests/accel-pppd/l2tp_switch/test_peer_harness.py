import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports


@pytest.mark.l2tp_switch
def test_peer_harness_against_plain_lns(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    cli_port, l2tp_port = alloc_ports(2)
    lns_config = config.make_tmp(
        f"""
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={l2tp_port}
    secret=testsecret
    """
    )
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + lns_config], accel_cmd, 5.0, cli_port=cli_port
    )
    assert started

    try:
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(l2tp_port),
                "--secret", "testsecret",
                "--calling-number", "472913",
            ],
        )
        rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
        assert rc == 0, err
        assert out.startswith("ok ")
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
        config.delete_tmp(lns_config)
