"""FIN_WAIT timeout of an ordinary (non-switch) L2TP tunnel.

After the peer's StopCCN, a tunnel without a switch target must stay in
FIN_WAIT for the full retransmission backoff, so a peer whose StopCCN is
retransmitted still finds the tunnel. A switch target's tunnel keeps the short
single-rtimeout window (see test_switch_downstream_idle_stopccn.py).
"""

import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, l2tp_finishing, wait_for

# rtimeout doubles up to `retransmit` times, capped at rtimeout-cap:
# 1 + 2 + 4 + 6 = 13s
RTIMEOUT = 1
RTIMEOUT_CAP = 6
RETRANSMIT = 4
FULL_BACKOFF_SUM_S = 13

# Past the single-rtimeout window (1s) and well short of the full 13s.
STILL_ALIVE_CHECK_S = 5.0


@pytest.mark.l2tp_switch
def test_ordinary_tunnel_survives_full_backoff_after_peer_stopccn(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    cli_port, l2tp_port = alloc_ports(2)

    cfg = config.make_tmp(
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
    rtimeout={RTIMEOUT}
    rtimeout-cap={RTIMEOUT_CAP}
    retransmit={RETRANSMIT}
    """
    )
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
    )
    assert started

    try:
        # Plain client: set up a tunnel and session, then send a tunnel-level
        # StopCCN. The config has no [l2tp-switch] section.
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(l2tp_port),
                "--secret", "testsecret",
                "--calling-number", "472913",
                "--send-stopccn",
            ],
        )
        rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 20.0)
        assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{out}"
        assert out.startswith("ok "), out

        # The daemon may not have read the StopCCN yet on a loaded host.
        finishing_seen = wait_for(
            lambda: l2tp_finishing(accel_cmd, cli_port)[0] == 1, 2.0
        )
        assert finishing_seen, (
            "tunnel never entered FIN_WAIT after the peer's StopCCN"
        )

        # Poll through the whole window so an early free is caught.
        deadline = time.monotonic() + STILL_ALIVE_CHECK_S
        while time.monotonic() < deadline:
            tunnels_finishing, _ = l2tp_finishing(accel_cmd, cli_port)
            assert tunnels_finishing == 1, (
                f"tunnel was freed within {STILL_ALIVE_CHECK_S}s of its "
                f"peer's StopCCN; short of the {FULL_BACKOFF_SUM_S}s full "
                f"retransmission-backoff window an ordinary tunnel must get "
                f"(rtimeout={RTIMEOUT}, rtimeout-cap={RTIMEOUT_CAP}, "
                f"retransmit={RETRANSMIT}). A lost ZLB ack would leave the "
                f"peer retransmitting its StopCCN into a tunnel that no "
                f"longer exists."
            )
            time.sleep(0.2)

        # FIN_WAIT must still end once the full backoff has elapsed.
        freed = wait_for(
            lambda: l2tp_finishing(accel_cmd, cli_port)[0] == 0,
            FULL_BACKOFF_SUM_S,
        )
        assert freed, (
            f"tunnel never left FIN_WAIT: still 'finishing' well past its "
            f"{FULL_BACKOFF_SUM_S}s full backoff window"
        )
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
        config.delete_tmp(cfg)
