import re

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports

# reconnect-interval= (seconds) written into the switch config, in place of the
# daemon's 5s default; the reconnect gap is asserted against it.
RECONNECT_INTERVAL = 1


@pytest.mark.l2tp_switch
def test_downstream_idle_stopccn_triggers_fast_reconnect(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    # A downstream peer may close an idle persistent target tunnel with a
    # graceful StopCCN. The switch must reconnect within its reconnect
    # interval.
    switch_cli, switch_l2tp, downstream_port = alloc_ports(3)

    switch_config = config.make_tmp(
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
    tcp=127.0.0.1:{switch_cli}
    [l2tp]
    port={switch_l2tp}
    secret=upstreamsecret
    [l2tp-switch]
    # Persistent, so the tunnel comes up at startup without a call.
    target=downstream,127.0.0.1,{downstream_port},downstreamsecret,persistent
    reconnect-interval={RECONNECT_INTERVAL}
    """
    )
    switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + switch_config], accel_cmd, 5.0, cli_port=switch_cli
    )
    assert switch_started

    try:
        # Fake downstream target: accepts the switch's tunnel, then sends a
        # StopCCN with no session. Two rounds: the first tunnel and the
        # reconnect.
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(downstream_port),
                "--secret", "downstreamsecret",
                "--send-stopccn",
                "--rounds", "2",
            ],
        )

        # Generous ceiling for the two-round run.
        rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 30.0)
        assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{out}"

        events = {}
        for m in re.finditer(r"event=(\S+) round=(\d+) t=([\d.]+)", out):
            events.setdefault(m.group(1), {})[int(m.group(2))] = float(m.group(3))

        assert 0 in events.get("sent_stopccn", {}), f"no stopccn in round 0:\n{out}"
        assert 1 in events.get("recv_sccrq", {}), f"no reconnect (round 1 SCCRQ):\n{out}"

        reconnect_gap = events["recv_sccrq"][1] - events["sent_stopccn"][0]

        # Nothing is left to retransmit after the StopCCN, so the gap should
        # be close to RECONNECT_INTERVAL.
        assert reconnect_gap < 5.0, (
            f"reconnect took {reconnect_gap:.1f}s after an idle, "
            f"session-less StopCCN; expected well under 5s\n{out}"
        )
    finally:
        accel_pppd_process.end(switch_thread, switch_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        config.delete_tmp(switch_config)
