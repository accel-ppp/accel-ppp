import pytest
from common import process, ipoe_iface


@pytest.fixture()
def accel_pppd_config(veth_pair_netns):
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


# sessions carry private state set up over generic netlink, a device made by
# rtnetlink would have none of it
@pytest.mark.dependency(depends=["ipoe_driver_loaded"], scope="session")
@pytest.mark.ipoe_driver
def test_ipoe_interface_cannot_be_created_by_iproute():
    (exit_code, out, err) = process.run(
        ["ip", "link", "add", "ipoetest0", "type", "ipoe"]
    )
    print("ip link add: exit=%d out=%s err=%s" % (exit_code, out, err))

    # remove it again in case it got created anyway, so that the rest of the
    # suite is not affected
    process.run(["ip", "link", "del", "ipoetest0"])

    assert exit_code != 0


# stale interfaces have to be removable without restarting accel-pppd, which
# would drop every remaining session
@pytest.mark.dependency(depends=["ipoe_driver_loaded"], scope="session")
@pytest.mark.ipoe_driver
def test_ipoe_interface_can_be_deleted_by_iproute(
    accel_pppd_instance, dhclient_instance, accel_cmd, veth_pair_netns
):
    assert accel_pppd_instance, "accel-pppd did not start"
    assert dhclient_instance["is_started"]
    assert ipoe_iface.wait_for_session(accel_cmd, veth_pair_netns["veth_a"])

    before = ipoe_iface.list_ipoe()
    print("ipoe interfaces: " + str(before))
    assert len(before) > 0

    (ifindex, name) = before[0]

    (exit_code, out, err) = process.run(["ip", "link", "del", name])
    print("ip link del %s: exit=%d out=%s err=%s" % (name, exit_code, out, err))
    assert exit_code == 0

    after = ipoe_iface.list_ipoe()
    print("ipoe interfaces after delete: " + str(after))
    assert (ifindex, name) not in after
