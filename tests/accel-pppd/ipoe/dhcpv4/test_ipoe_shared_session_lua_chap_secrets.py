import pytest
from common import process
import time


# create vlan 335 on both interfaces of pair
@pytest.fixture()
def veth_pair_vlans_config():
    return {"vlans_a": [335], "vlans_b": [335]}


# use vlan as a username
@pytest.fixture()
def chap_secrets_config(veth_pair_netns):
    return "335     *           pass123   192.0.2.67"


# return vlan as a username
@pytest.fixture()
def lua_script():
    return """#!lua
    function vlan_func(pkt)
      return pkt:vlan()
    end"""


@pytest.fixture()
def accel_pppd_config(veth_pair_netns, chap_secrets_config_file, lua_script_file):
    print(
        "accel_pppd_config veth_pair_netns: "
        + str(veth_pair_netns)
        + "chap_secrets_config_file: "
        + str(chap_secrets_config_file)
    )
    return (
        """
    [modules]
    connlimit
    chap-secrets
    ipoe

    [cli]
    tcp=127.0.0.1:2001

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [ipoe]
    lua-file="""
        + lua_script_file
        + """
    username=lua:vlan_func
    password=pass123
    verbose=5
    start=dhcpv4
    shared=1
    gw-ip-address=192.0.2.1/24
    interface=re:."""
        + veth_pair_netns["veth_a"][1:]
        + "\\.335"
        + """
    [chap-secrets]
    chap-secrets="""
        + chap_secrets_config_file
    )


# test dhcpv4 shared session without auth check
@pytest.mark.dependency(depends=["ipoe_driver_loaded"], scope="session")
@pytest.mark.ipoe_driver
def test_ipoe_shared_session_lua_chap_secrets(
    dhclient_instance, accel_cmd, veth_pair_netns
):

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
        if veth_pair_netns["veth_a"] in out and "192.0.2.67" in out and "active" in out:
            # session is found
            print(
                "test_ipoe_session_lua_chap_secrets: session found in (sec): "
                + str(sleep_time)
            )
            is_started = True
            break
        time.sleep(0.1)
        sleep_time += 0.1

    print("test_ipoe_shared_session_lua_chap_secrets: last accel-cmd out: " + out)

    # test that session is started
    assert is_started == True
