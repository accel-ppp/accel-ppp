import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, switch_show, wait_for, wait_up


@pytest.mark.l2tp_switch
def test_downstream_failure_does_not_affect_locally_terminated_session(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """A switched call and a locally terminated call share one upstream tunnel.
    When the switched call's downstream leg fails, only that call may be
    affected; the tunnel and the other session must survive.
    """
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

            # Place a switched call (472913) and, on the same tunnel, a call whose
            # calling number matches no match= entry, so the switch terminates it locally.
            #
            # --hold-seconds keeps the upstream socket open during teardown. Otherwise
            # the CDN sent when the downstream fails hits a closed port, and the ICMP
            # unreachable takes down the whole upstream tunnel.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--second-call", "999999",
                    "--hold-seconds", "20",
                ],
            )

            out = ""
            def active_1():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 1" in out

            assert wait_for(active_1, 5.0), out

            (exit, sessions_out, err) = process.run([accel_cmd, "-p", str(switch_cli), "show sessions"])
            assert "999999" in sessions_out, sessions_out

            # End the downstream instance. The switched call's leg fails, and the
            # local call (999999) must be unaffected. Check right away because the fake
            # second call has no PPP client and eventually times out on its own.
            accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)

            out = ""
            def active_0():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 0" in out

            assert wait_for(active_0, 5.0), out

            (exit, sessions_out, err) = process.run([accel_cmd, "-p", str(switch_cli), "show sessions"])
            assert exit == 0
            assert "999999" in sessions_out, (
                "locally-terminated session was torn down alongside the "
                "unrelated switched call's failure:\n" + sessions_out
            )

            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 30.0)
            assert rc == 0, err
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
