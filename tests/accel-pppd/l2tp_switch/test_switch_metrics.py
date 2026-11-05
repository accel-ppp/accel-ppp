import pytest
import http.client
import time
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, start_instance, wait_up

DATA_PATTERN = "SWITCHOK"

# Must match idle-linger= in the [l2tp-switch] configs below.
IDLE_LINGER = 4.0


def _metrics_request(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        return resp.status, body
    finally:
        conn.close()


def _target_up(body, target="downstream"):
    needle = f'accel_ppp_l2tp_switch_target_up{{target="{target}"}} '
    for line in body.splitlines():
        if line.startswith(needle):
            return line.rsplit(" ", 1)[1] == "1"
    raise AssertionError(f"target_up metric missing for {target!r}:\n{body}")


def _wait_for_target_up(expected, timeout, port, target="downstream"):
    """Poll /metrics until target_up matches `expected`.

    Return (found, elapsed seconds, last body).
    """
    started = time.monotonic()
    body = ""
    while time.monotonic() - started < timeout:
        status, body = _metrics_request(port)
        assert status == 200
        if _target_up(body, target) == expected:
            return True, time.monotonic() - started, body
        time.sleep(0.1)
    return False, time.monotonic() - started, body


@pytest.mark.l2tp_switch
def test_switch_metrics_exposed_via_native_endpoint(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    switch_cli, down_cli, switch_l2tp, down_l2tp, metrics_port = alloc_ports(5)
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, down_cli, "127.0.0.1", down_l2tp, "downstreamsecret"
    )
    assert d_started

    try:
        # start_instance() fixes [modules] to log_file/l2tp and a second [modules]
        # section in extra= is not merged, so build the config here with metrics
        # loaded from the start.
        s_cfg = config.make_tmp(
            f"""
    [modules]
    log_file
    l2tp
    metrics

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{switch_cli}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={switch_l2tp}
    secret=upstreamsecret

    [l2tp-switch]
    # Persistent target, so its tunnel is already up when the call arrives.
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream

    [metrics]
    address=127.0.0.1:{metrics_port}
    allowed_ips=127.0.0.0/8
    """
        )
        s_started, s_thread, s_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + s_cfg], accel_cmd, 5.0, cli_port=switch_cli
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

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

            body = None
            for _ in range(50):
                status, body = _metrics_request(metrics_port)
                assert status == 200
                if 'accel_ppp_l2tp_switch_target_active{target="downstream"} 1' in body:
                    break
                time.sleep(0.1)

            assert "accel_ppp_l2tp_switch_active 1" in body, body
            assert 'accel_ppp_l2tp_switch_target_up{target="downstream"} 1' in body, body
            assert 'accel_ppp_l2tp_switch_target_active{target="downstream"} 1' in body, body

            # The harness writes upstream to the target, which is the target's tx
            # direction (bytes_out in l2tp switch show).
            tx_line = next(
                line for line in body.splitlines()
                if line.startswith('accel_ppp_l2tp_switch_target_bytes_total{target="downstream",direction="tx"}')
            )
            tx_bytes = int(tx_line.rsplit(" ", 1)[1])
            assert tx_bytes >= len(DATA_PATTERN), tx_line
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_metrics_target_up_tracks_on_demand_lifecycle(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """accel_ppp_l2tp_switch_target_up for an on-demand target is 0 at rest, 1
    once a call connects, and still 1 through the idle-linger window after
    the call ends (only target_active drops to 0). It returns to 0 once the
    linger closes the tunnel.

    The downstream is the peer harness in --listen --hold-seconds mode, since a
    real accel-ppp downstream closes within about a second of the call ending
    and would race the linger.
    """
    switch_cli, switch_l2tp, down_l2tp, metrics_port = alloc_ports(4)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "45",
        ],
    )

    try:
        s_cfg = config.make_tmp(
            f"""
    [modules]
    log_file
    l2tp
    metrics

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{switch_cli}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={switch_l2tp}
    secret=upstreamsecret

    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    idle-linger=4
    match=Calling-Number,exact,472913,downstream

    [metrics]
    address=127.0.0.1:{metrics_port}
    allowed_ips=127.0.0.0/8
    """
        )
        s_started, s_thread, s_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + s_cfg], accel_cmd, 5.0, cli_port=switch_cli
        )
        assert s_started

        try:
            status, body = _metrics_request(metrics_port)
            assert status == 200
            assert not _target_up(body), (
                f"on-demand target's target_up is set with no call ever"
                f" placed:\n{body}"
            )

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                    "--send-stopccn",
                ],
            )

            up, _, body = _wait_for_target_up(True, 8.0, metrics_port)
            assert up, f"target_up never went to 1 once connected:\n{body}"

            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 20.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            # Wait for the call to end (target_active back to 0), then check that
            # target_up is still 1 well inside the linger window.
            active_zero = False
            body = ""
            started = time.monotonic()
            while time.monotonic() - started < 15.0:
                status, body = _metrics_request(metrics_port)
                assert status == 200
                if 'accel_ppp_l2tp_switch_target_active{target="downstream"} 0' in body:
                    active_zero = True
                    break
                time.sleep(0.1)
            assert active_zero, f"call never ended:\n{body}"

            time.sleep(IDLE_LINGER * 0.4)
            status, body = _metrics_request(metrics_port)
            assert status == 200
            assert 'accel_ppp_l2tp_switch_target_active{target="downstream"} 0' in body, body
            assert _target_up(body), (
                "target_up dropped before the idle-linger window closed the"
                f" tunnel:\n{body}"
            )

            down, elapsed, body = _wait_for_target_up(
                False, IDLE_LINGER, metrics_port
            )
            assert down, (
                f"target_up never dropped to 0 once the linger fired"
                f" ({elapsed:.1f}s):\n{body}"
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = l2tp_peer_process.wait(down_thread, down_ctrl, 60.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"


@pytest.mark.l2tp_switch
def test_switch_metrics_target_up_false_while_still_connecting(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """target_up reads 0 while the on-demand target's tunnel exists but has not
    reached STATE_ESTB yet.

    The downstream delays its SCCRP (--sccrp-delay-ms), and the calling harness
    stays up with --hold-seconds, because a hang-up would tear down the queued
    call before it is placed.
    """
    sccrp_delay = 3.0

    switch_cli, switch_l2tp, down_l2tp, metrics_port = alloc_ports(4)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
        ],
    )

    try:
        s_cfg = config.make_tmp(
            f"""
    [modules]
    log_file
    l2tp
    metrics

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{switch_cli}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={switch_l2tp}
    secret=upstreamsecret

    [l2tp-switch]
    target=slow,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    idle-linger=4
    match=Calling-Number,exact,472913,slow

    [metrics]
    address=127.0.0.1:{metrics_port}
    allowed_ips=127.0.0.0/8
    """
        )
        s_started, s_thread, s_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + s_cfg], accel_cmd, 5.0, cli_port=switch_cli
        )
        assert s_started

        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    # Outlives the stalled connect so the call is still live at the check.
                    "--hold-seconds", "10",
                ],
            )

            try:
                # Mid-connect: the tunnel exists but the delayed SCCRP keeps it out of
                # STATE_ESTB, so target_up must read 0.
                time.sleep(sccrp_delay * 0.5)
                status, body = _metrics_request(metrics_port)
                assert status == 200
                assert not _target_up(body, "slow"), (
                    "target_up is already 1 while the downstream tunnel"
                    f" is still negotiating (not yet STATE_ESTB):\n{body}"
                )

                # target_up goes to 1 once the slow downstream finishes negotiating.
                up, _, body = _wait_for_target_up(
                    True, 8.0, metrics_port, "slow"
                )
                assert up, f"target_up never went to 1 once connected:\n{body}"
            finally:
                rc, harness_out, err = finish_harness(peer_thread, peer_ctrl, 20.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 20.0)
        assert down_rc == 0, f"listener exited with {down_rc}:\n{down_err}"
