import pytest
from common import netns


# create vlan 15 only in netns (invisble to accel-pppd)
@pytest.fixture()
def veth_pair_vlans_config():
    return {"vlans_a": [], "vlans_b": [15]}


@pytest.fixture()
def accel_pppd_config(veth_pair_netns):
    print(veth_pair_netns)
    return """
    [modules]
    radius
    pppoe

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [radius]

    [pppoe]
    ac-name=test-accel
    vlan-mon=%s,10-20
    interface=re:%s.\\d+
    """ % (
        veth_pair_netns["veth_a"],
        veth_pair_netns["veth_a"],
    )


# test pppoe discovery in vlan created by vlan_mon
@pytest.mark.dependency(depends=["vlan_mon_driver_loaded"], scope="session")
@pytest.mark.vlan_mon_driver
def test_pppoe_vlan_mon(accel_pppd_instance, veth_pair_netns):

    # test that accel-pppd started successfully
    assert accel_pppd_instance

    (exit_sh_stat, out_sh_stat, err_sh_stat) = netns.exec(
        veth_pair_netns["netns"],
        ["pppoe-discovery", "-I", veth_pair_netns["veth_b"] + ".15"],
    )

    # test that ac-name=test-accel is in pppoe-discovery reply (PADO)
    assert exit_sh_stat == 0 and err_sh_stat == "" and "test-accel" in out_sh_stat
