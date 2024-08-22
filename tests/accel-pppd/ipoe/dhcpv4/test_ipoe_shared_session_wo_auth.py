import pytest
from common import process
import time


@pytest.fixture()
def accel_pppd_config(veth_pair_netns):
    print("accel_pppd_config veth_pair_netns: " + str(veth_pair_netns))
    return (
        """
    [modules]
    connlimit
    radius
    ipoe
    ippool

    [ip-pool]
    gw-ip-address=192.0.2.1
    192.0.2.2-255

    [cli]
    tcp=127.0.0.1:2001

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [radius]

    [ipoe]
    noauth=1
    shared=1
    gw-ip-address=192.0.2.1/24
    interface=re:."""
        + veth_pair_netns["veth_a"][1:]
    )


# test dhcpv4 shared session without auth check
@pytest.mark.dependency(depends=["ipoe_driver_loaded"], scope = 'session')
@pytest.mark.ipoe_driver
def test_ipoe_shared_session_wo_auth(dhclient_instance, accel_cmd, veth_pair_netns):

    # test that dhclient (with accel-pppd) started successfully
    assert dhclient_instance["is_started"]

    # wait until session is started
    max_wait_time = 10.0
    sleep_time = 0.0
    is_started = False  # is session started
    while sleep_time < max_wait_time:
        (exit, out, err) = process.run(
            [
                accel_cmd,
                "show sessions called-sid,ip,state",
            ]
        )
        assert exit == 0  # accel-cmd fails
        # print(out)
        if veth_pair_netns["veth_a"] in out and "192.0.2." in out and "active" in out:
            # session is found
            print(
                "test_pppoe_session_wo_auth: session found in (sec): " + str(sleep_time)
            )
            is_started = True
            break
        time.sleep(0.1)
        sleep_time += 0.1

    print("test_ipoe_shared_session_wo_auth: last accel-cmd out: " + out)

    # test that session is started
    assert is_started == True
