import pytest
from common import netns, process
import time

# This test module requires pppoe-discovery with -a and -t options
# Ubuntu 20.04 has not this option, Ubuntu 22.04 is ok

# Check that pppoe-discover supports -a and -t (to disable some tests required these features)
def support_pppoe_discovery_a_t():
    try:
        (_, out, err) = process.run(["pppoe-discovery", "-h"])
    except:  # can't run pppoe-discovery
        return False

    if "-t " in out + err and "-a " in out + err:  # found -t and -a options
        return True
    else:
        return False


# skip tests in this module if pppoe-discovery doesn't support '-a' and '-t' options
pytestmark = pytest.mark.skipif(
    not support_pppoe_discovery_a_t(), reason="bad pppoe-discovery"
)


@pytest.fixture()
def accel_pppd_config(veth_pair_netns):
    print(veth_pair_netns)
    return (
        """
    [modules]
    pppoe

    [log]
    log-debug=/dev/stdout
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [pppoe]
    ac-name=test-accel
    pado-delay=1500
    interface="""
        + veth_pair_netns["veth_a"]
    )


# test pado delay. accel-pppd is configured for 1.5s delay
# first step: test that pppoe-discovery fails if wait timeout=1<1.5
# second step: test that pppoe-discovery gets pado if wait timeout=2>1.5
def test_pppoe_pado_delay(accel_pppd_instance, veth_pair_netns):

    # test that accel-pppd started successfully
    assert accel_pppd_instance

    # send two times with wait timeout = 1
    (exit_sh_stat, out_sh_stat, err_sh_stat) = netns.exec(
        veth_pair_netns["netns"],
        ["pppoe-discovery", "-a1", "-t1", "-I", veth_pair_netns["veth_b"]],
    )
    time.sleep(1)  # sleep for one second (because accel-pppd replies in this timeslot)
    (exit_sh_stat2, out_sh_stat2, err_sh_stat2) = netns.exec(
        veth_pair_netns["netns"],
        ["pppoe-discovery", "-a1", "-t1", "-I", veth_pair_netns["veth_b"]],
    )
    time.sleep(1)  # sleep for one second (because accel-pppd replies in this timeslot)

    # print(out_sh_stat + err_sh_stat)
    # print(out_sh_stat2 + err_sh_stat2)

    # test that pppoe-discovery (wait timeout 1s) fails (as expected) (two times)
    assert exit_sh_stat != 0 and "test-accel" not in out_sh_stat
    assert exit_sh_stat2 != 0 and "test-accel" not in out_sh_stat2

    (exit_sh_stat3, out_sh_stat3, err_sh_stat3) = netns.exec(
        veth_pair_netns["netns"],
        ["pppoe-discovery", "-a1", "-t2", "-I", veth_pair_netns["veth_b"]],
    )

    # test that pppoe-discovery (wait timeout 2s) gets pado
    assert exit_sh_stat3 == 0 and "test-accel" in out_sh_stat3
