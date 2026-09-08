import pytest
import http.client
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance

DATA_PATTERN = "SWITCHOK"
METRICS_PORT = 9198


def _metrics_request():
    conn = http.client.HTTPConnection("127.0.0.1", METRICS_PORT, timeout=5)
    try:
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        return resp.status, body
    finally:
        conn.close()


@pytest.mark.l2tp_switch
def test_switch_metrics_exposed_via_native_endpoint(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17090, "downstreamsecret"
    )
    assert d_started

    try:
        # helpers.start_instance()'s [modules] is fixed to log_syslog/l2tp --
        # a second [modules] section in extra= is NOT merged with the first
        # (confirmed on a real VM: the metrics module silently never loads,
        # /metrics connection refused), so this test builds its own config
        # from scratch instead, with metrics listed alongside l2tp from the
        # start.
        s_cfg = config.make_tmp(
            f"""
    [modules]
    log_syslog
    l2tp
    metrics

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port=17091
    secret=upstreamsecret

    [l2tp-switch]
    target=downstream,127.0.0.1,17090,downstreamsecret
    match=Calling-Number,exact,472913,downstream

    [metrics]
    address=127.0.0.1:{METRICS_PORT}
    allowed_ips=127.0.0.0/8
    """
        )
        s_started, s_thread, s_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + s_cfg], accel_cmd, 5.0, cli_port=2001
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
                    "--peer-port", "17091",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            body = None
            for _ in range(50):
                status, body = _metrics_request()
                assert status == 200
                if 'accel_ppp_l2tp_switch_target_active{target="downstream"} 1' in body:
                    break
                time.sleep(0.1)

            assert "accel_ppp_l2tp_switch_active 1" in body, body
            assert 'accel_ppp_l2tp_switch_target_up{target="downstream"} 1' in body, body
            assert 'accel_ppp_l2tp_switch_target_active{target="downstream"} 1' in body, body

            # the harness's write travels upstream (MK) -> target, i.e. the
            # target's own "tx" direction -- matches l2tp switch show's
            # bytes_out framing for the per-target line.
            tx_line = next(
                line for line in body.splitlines()
                if line.startswith('accel_ppp_l2tp_switch_target_bytes_total{target="downstream",direction="tx"}')
            )
            tx_bytes = int(tx_line.rsplit(" ", 1)[1])
            assert tx_bytes >= len(DATA_PATTERN), tx_line
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
