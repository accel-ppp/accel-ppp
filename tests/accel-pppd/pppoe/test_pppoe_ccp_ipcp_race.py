import pytest
from common import process, config
import time


# accel-pppd log file (separate file, because stdout of accel-pppd is piped
# by the test harness and is not readable while the test is running)
@pytest.fixture()
def accel_pppd_log_file():
    # test setup:
    filename = config.make_tmp("")

    # test execution:
    yield filename

    # test teardown:
    config.delete_tmp(filename)


@pytest.fixture()
def chap_secrets_config():
    return "loginRACE     *           pass123   192.0.2.38"


# 'mppe=prefer' makes CCP non-passive, so CCP negotiation is still in progress
# when the peer sends its IPCP ConfReq
@pytest.fixture()
def accel_pppd_config(veth_pair_netns, chap_secrets_config_file, accel_pppd_log_file):
    return (
        """
    [modules]
    log_file
    chap-secrets
    pppoe
    auth_mschap_v2

    [core]
    log-error=/dev/stderr

    [ppp]
    verbose=1
    mppe=prefer

    [log]
    log-debug="""
        + accel_pppd_log_file
        + """
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [pppoe]
    interface="""
        + veth_pair_netns["veth_a"]
        + """
    [chap-secrets]
    gw-ip-address=192.0.2.1
    chap-secrets="""
        + chap_secrets_config_file
    )


# pppd does not require MPPE, so it rejects the MPPE option offered by
# accel-pppd (which costs CCP an additional round trip) and does not delay
# IPCP until CCP is done
@pytest.fixture()
def pppd_config(veth_pair_netns):
    return (
        """
    nodetach
    noipdefault
    noauth
    persist
    mtu 1492
    noaccomp
    default-asyncmap
    lcp-echo-interval 0
    user loginRACE
    password pass123
    nic-"""
        + veth_pair_netns["veth_b"]
    )


# IPCP ConfReq received while CCP is still negotiating must not be answered
# with a TermAck: the ack is withheld and sent when CCP is done
@pytest.mark.chap_secrets
def test_pppoe_ccp_ipcp_race(pppd_instance, accel_cmd, accel_pppd_log_file):

    # test that pppd (with accel-pppd) started successfully
    assert pppd_instance["is_started"]

    # wait until session is started
    max_wait_time = 10.0
    sleep_time = 0.0
    is_started = False  # is session started
    while sleep_time < max_wait_time:
        (exit, out, err) = process.run(
            [
                accel_cmd,
                "show sessions match username log.nRACE username,ip,state",
            ]
        )
        assert exit == 0  # accel-cmd fails
        if "loginRACE" in out and "192.0.2.38" in out and "active" in out:
            print("test_pppoe_ccp_ipcp_race: session found in (sec): " + str(sleep_time))
            is_started = True
            break
        time.sleep(0.1)
        sleep_time += 0.1

    print("test_pppoe_ccp_ipcp_race: last accel-cmd out: " + out)

    # test that session is started
    assert is_started == True

    with open(accel_pppd_log_file, "r") as f:
        log = f.read().splitlines()
    print("test_pppoe_ccp_ipcp_race: accel-pppd log:\n" + "\n".join(log))

    ccp_started = [i for i, line in enumerate(log) if "ccp_layer_started" in line]
    assert len(ccp_started) > 0  # CCP was negotiated

    # skip if the peer did not send its IPCP ConfReq before CCP was done,
    # in this case there is nothing to check
    conf_req = [
        i
        for i, line in enumerate(log[: ccp_started[0]])
        if "recv [IPCP ConfReq" in line
    ]
    if len(conf_req) == 0:
        pytest.skip("peer did not send IPCP ConfReq while CCP was negotiating")

    # test that IPCP ConfReq was not answered with a TermAck
    assert len([line for line in log if "send [IPCP TermAck" in line]) == 0
