import pytest
from common import process
import time


@pytest.fixture()
def accel_pppd_config(veth_pair_netns):
    print("accel_pppd_config veth_pair_netns: " + str(veth_pair_netns))
    return (
        """
    [modules]
    radius
    pppoe
    auth_pap
    ippool

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [auth]
    any-login=1

    [ip-pool]
    gw-ip-address=192.0.2.1
    192.0.2.2-255

    [cli]
    tcp=127.0.0.1:2001

    [radius]

    [pppoe]
    interface="""
        + veth_pair_netns["veth_a"]
    )


@pytest.fixture()
def pppd_config(veth_pair_netns):
    print("pppd_config veth_pair_netns: " + str(veth_pair_netns))
    return (
        """
    nodetach
    noipdefault
    defaultroute
    connect /bin/true
    noauth
    persist
    mtu 1492
    noaccomp
    default-asyncmap
    user loginAB
    password pass123
    nic-"""
        + veth_pair_netns["veth_b"]
    )


# test pppoe session without auth check
def test_pppoe_session_wo_auth(pppd_instance, accel_cmd):

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
                "show sessions match username log.nAB username,ip,state",
            ]
        )
        assert exit == 0  # accel-cmd fails
        # print(out)
        if "loginAB" in out and "192.0.2." in out and "active" in out:
            # session is found
            print(
                "test_pppoe_session_wo_auth: session found in (sec): " + str(sleep_time)
            )
            is_started = True
            break
        time.sleep(0.1)
        sleep_time += 0.1

    print("test_pppoe_session_wo_auth: last accel-cmd out: " + out)

    # test that session is started
    assert is_started == True
