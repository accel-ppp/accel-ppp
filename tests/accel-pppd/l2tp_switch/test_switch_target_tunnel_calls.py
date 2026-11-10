import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process, process
from helpers import alloc_ports, finish_harness, start_instance, switch_show, wait_up


@pytest.mark.l2tp_switch
@pytest.mark.parametrize("rule_matches", [True, False], ids=["matching-rule", "no-rule"])
def test_downstream_icrq_on_target_tunnel_is_rejected(
    pytestconfig, accel_cmd, accel_pppd, peer_bin, rule_matches
):
    """The target tunnel is outbound: an ICRQ from its peer must be refused
    with a CDN, neither becoming a local PPP session (no rule) nor a switched
    call back through the same target (matching rule), and the tunnel stays up."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    rule = "match=Calling-Number,exact,472913,downstream" if rule_matches else "match=Calling-Number,exact,999,downstream"

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--icrq-after-ms", "500",
            "--hold-seconds", "6",
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
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    {rule}
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # The ICRQ goes out 0.5 s after the tunnel is established.
            time.sleep(2)

            out = switch_show(accel_cmd, switch_cli)
            assert "[up]" in out, out
            assert "matched: 0" in out, out
            (exit_code, sessions, err) = process.run([accel_cmd, "-p", str(switch_cli), "show sessions"])
            assert exit_code == 0, err
            assert "l2tp" not in sessions, sessions

            rc, dout, derr = l2tp_peer_process.wait(down_thread, down_ctrl, 15.0)
            assert rc == 0, derr
            m = re.search(r"event=recv_cdn round=0 t=\S+ res=(\d+) err=(\d+)", dout)
            assert m, dout
            assert (m.group(1), m.group(2)) == ("2", "6"), dout
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 10.0)
