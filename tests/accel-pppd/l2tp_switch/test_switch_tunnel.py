import pytest
import time
from common import process, config, accel_pppd_process


@pytest.mark.l2tp_switch
def test_switch_tunnel_comes_up(pytestconfig, accel_cmd, accel_pppd):
    # downstream ("customer") LNS instance, plain L2TP LNS on port 12345
    downstream_config = config.make_tmp(
        """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2101
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port=12345
    secret=downstreamsecret
    """
    )
    # cli_port=2101 -- this instance's own [cli] tcp= above, which isn't
    # accel-cmd's default port (2001, used by the switch instance below);
    # without it, the readiness/shutdown checks silently target the wrong
    # port for the whole max_wait_time instead of ever reaching this daemon.
    downstream_started, downstream_thread, downstream_ctrl = (
        accel_pppd_process.start(
            accel_pppd, ["-c" + downstream_config], accel_cmd, 5.0,
            cli_port=2101,
        )
    )
    assert downstream_started

    try:
        # switch instance, pointing a target at the downstream instance
        switch_config = config.make_tmp(
            """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [l2tp]
    secret=upstreamsecret
    [l2tp-switch]
    target=downstream,127.0.0.1,12345,downstreamsecret
    """
        )
        switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + switch_config], accel_cmd, 5.0
        )
        assert switch_started

        try:
            up = False
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])
                assert exit == 0
                if "downstream -> 127.0.0.1:12345 [up]" in out:
                    up = True
                    break
                time.sleep(0.1)

            assert up
        finally:
            accel_pppd_process.end(switch_thread, switch_ctrl, accel_cmd, 10.0)
    finally:
        accel_pppd_process.end(
            downstream_thread, downstream_ctrl, accel_cmd, 10.0, cli_port=2101
        )
        config.delete_tmp(downstream_config)
