import re

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, finish_harness, start_instance, wait_up


def _got_cdn(out):
    """(message type, result, error) of the call-ending message the upstream
    harness decoded: a CDN, or a StopCCN that would only mimic one."""
    m = re.search(r"event=got_cdn type=(\w+) res=(\d+) err=(\d+)", out)
    assert m, out
    return m.groups()


@pytest.mark.l2tp_switch
def test_downstream_cdn_result_reaches_upstream(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """A call ended by the downstream must tell the upstream why: the CDN it
    gets carries the downstream's result code, not a generic error."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    # The harness ends the call with a CDN of result 4 (administrative:
    # no resources), error 7: distinct from anything the switch itself would
    # pick (2/6, 3/0) and from the harness default (1/0).
    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--cdn-after-iccn-ms", "300",
            "--cdn-result", "4:7",
            "--hold-seconds", "30",
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
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
            assert rc == 0, err

            assert _got_cdn(out) == ("cdn", "4", "7"), out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)


@pytest.mark.l2tp_switch
def test_downstream_cdn_result_reaches_upstream_under_traffic(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """The result must survive frames in flight: the upstream keeps sending
    PPP frames while the downstream ends the call, and the switch's splice
    sees the downstream leg gone before its relay hop runs."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--cdn-after-iccn-ms", "700",
            "--cdn-result", "5:9",
            "--hold-seconds", "30",
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
    match=Calling-Number,exact,472913,downstream
    """,
            thread_count=4,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", "A" * 100,
                    "--data-count", "400000",
                    "--wait-cdn",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(thread, ctrl, 60.0)
            assert rc == 0, err

            assert _got_cdn(out) == ("cdn", "5", "9"), out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)


@pytest.mark.l2tp_switch
def test_upstream_cdn_result_reaches_downstream(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """The relay works both ways: a call ended by the upstream tells the
    downstream why, with the upstream's own result code."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "8",
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
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    # the downstream ICCN is long in by then
                    "--send-cdn", "5:9",
                    "--send-cdn-delay-ms", "1500",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(thread, ctrl, 15.0)
            assert rc == 0, err
            assert "event=sent_cdn_up" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)

    assert "event=recv_iccn" in down_out, down_out
    m = re.search(r"event=recv_cdn round=0 t=[\d.]+ res=(\d+) err=(\d+)", down_out)
    assert m, down_out
    assert (m.group(1), m.group(2)) == ("5", "9"), down_out


@pytest.mark.l2tp_switch
@pytest.mark.parametrize(
    "downstream_code, expected",
    [
        # RFC 2661 4.4.2 defines 1-11: passed on as they came
        ("6:1", ("cdn", "6", "1")),
        ("8:3", ("cdn", "8", "3")),
        ("11:5", ("cdn", "11", "5")),
        # reserved or undefined: the generic 2/6 (error condition)
        ("0:1", ("cdn", "2", "6")),
        ("12:1", ("cdn", "2", "6")),
        ("65535:9", ("cdn", "2", "6")),
    ],
)
def test_downstream_cdn_result_is_relayed_only_if_defined(
    pytestconfig, accel_cmd, accel_pppd, peer_bin, downstream_code, expected
):
    """Only the CDN result codes of RFC 2661 (1-11) are passed upstream;
    anything else the downstream sends becomes the generic 2/6."""
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--cdn-after-iccn-ms", "300",
            "--cdn-result", downstream_code,
            "--hold-seconds", "30",
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
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            thread, ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(thread, ctrl, 10.0)
            assert rc == 0, err

            assert _got_cdn(out) == expected, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 5.0)
