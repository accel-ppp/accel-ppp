import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance


@pytest.mark.l2tp_switch
def test_downstream_failure_does_not_affect_locally_terminated_session(
    pytestconfig, accel_cmd, accel_pppd
):
    """A real upstream tunnel plausibly carries both switched calls and
    ordinary, locally-terminated calls side by side -- only the calling
    numbers listed under [l2tp-switch] match= get switched, everything
    else on the same tunnel goes through accel-ppp's own normal PPP
    stack. When one switched call's downstream leg fails, only that one
    call may be affected: the shared upstream tunnel and any other,
    unrelated session riding on it (switched or not) must survive.
    """
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17100, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17101,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17100,downstreamsecret
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            # place a switched call (472913, matches the match= entry above)
            # and, on the *same* tunnel, a second call with a calling number
            # that does NOT match any match= entry -- an ordinary,
            # locally-terminated call on the switch instance's own PPP stack.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17101",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--second-call", "999999",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            active = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                if "active: 1" in out:
                    active = 1
                    break
                time.sleep(0.1)
            assert active == 1, out

            (exit, sessions_out, err) = process.run([accel_cmd, "-p", "2001", "show sessions"])
            assert "999999" in sessions_out, sessions_out

            # gracefully end the downstream instance -- the switched call's
            # own leg fails, but the locally-terminated call (999999) on the
            # same upstream tunnel must be completely unaffected. Check
            # promptly: the fake second call has no real PPP client behind
            # it, so it eventually times out on its own (unrelated to this
            # test) after a while -- the assertion here is about the moment
            # right after the switched call's own teardown, not the second
            # call's own eventual, unrelated lifecycle.
            accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)

            active = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                assert exit == 0
                if "active: 0" in out:
                    active = 0
                    break
                time.sleep(0.1)
            assert active == 0, out

            (exit, sessions_out, err) = process.run([accel_cmd, "-p", "2001", "show sessions"])
            assert exit == 0
            assert "999999" in sessions_out, (
                "locally-terminated session was torn down alongside the "
                "unrelated switched call's failure:\n" + sessions_out
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)
