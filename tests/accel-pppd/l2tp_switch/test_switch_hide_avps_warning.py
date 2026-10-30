import pytest
from common import config, accel_pppd_process
from helpers import alloc_ports, read_log, start_instance

WARNING = "hide-avps is not set"


def _log_with_target(accel_cmd, accel_pppd, l2tp_extra):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        switch_cli,
        "127.0.0.1",
        switch_l2tp,
        "upstreamsecret",
        l2tp_extra=l2tp_extra,
        extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started
    try:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        return read_log(s_cfg)
    finally:
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_warns_once_when_target_configured_without_hide_avps(pytestconfig, accel_cmd, accel_pppd):
    """Proxied PAP credentials cross the downstream leg in the clear unless
    hide-avps=1; say so once at startup."""
    log = _log_with_target(accel_cmd, accel_pppd, "")

    assert log.count(WARNING) == 1, log


@pytest.mark.l2tp_switch
def test_no_warning_with_hide_avps(pytestconfig, accel_cmd, accel_pppd):
    log = _log_with_target(accel_cmd, accel_pppd, "hide-avps=1")

    assert WARNING not in log, log
