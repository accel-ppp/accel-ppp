import pytest
from common import netns


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
    interface="""
        + veth_pair_netns["veth_a"]
    )


# test pppoe discovery
def test_pppoe_discovery(accel_pppd_instance, veth_pair_netns):

    # test that accel-pppd started successfully
    assert accel_pppd_instance

    (exit_sh_stat, out_sh_stat, err_sh_stat) = netns.exec(
        veth_pair_netns["netns"], ["pppoe-discovery", "-I", veth_pair_netns["veth_b"]]
    )

    # test that ac-name=test-accel is in pppoe-discovery reply (PADO)
    assert (
        exit_sh_stat == 0
        and err_sh_stat == ""
        and "test-accel" in out_sh_stat
    )
