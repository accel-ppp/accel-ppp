import pytest
from common import accel_pppd_process, ipoe_iface


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


# accel-pppd killed with SIGKILL has no chance to remove the session
# interfaces it created, so they are left in the kernel. The next instance is
# supposed to drop them while starting up.
@pytest.mark.dependency(depends=["ipoe_driver_loaded"], scope="session")
@pytest.mark.ipoe_driver
def test_ipoe_stale_interfaces_removed_after_sigkill(
    accel_pppd_instance,
    dhclient_instance,
    accel_cmd,
    accel_pppd,
    accel_pppd_config_file,
    veth_pair_netns,
    pytestconfig,
):
    assert accel_pppd_instance, "accel-pppd did not start"
    assert dhclient_instance["is_started"]
    assert ipoe_iface.wait_for_session(accel_cmd, veth_pair_netns["veth_a"])

    # the session must have created an interface, otherwise there is nothing
    # for this test to check
    before = ipoe_iface.list_ipoe()
    print("ipoe interfaces before the crash: " + str(before))
    assert len(before) > 0

    assert ipoe_iface.kill_accel_pppd() > 0

    # nothing removes them while no accel-pppd is running (not asserted, the
    # kernel module is free to start doing it on its own one day)
    print("ipoe interfaces after the crash: " + str(ipoe_iface.list_ipoe()))

    # start again, it replies to 'show version' only once the startup flush is
    # done, so there is no need to wait for anything else
    (is_started, thread, control) = accel_pppd_process.start(
        accel_pppd,
        ["-c" + accel_pppd_config_file],
        accel_cmd,
        pytestconfig.getoption("accel_pppd_max_wait_time"),
    )

    try:
        assert is_started

        after = ipoe_iface.list_ipoe()
        print("ipoe interfaces after the restart: " + str(after))

        # compared by ifindex: dhclient may get a new session in the meantime,
        # and the fresh interface would reuse the ipoe0 name
        stale = set(before) & set(after)
        assert not stale, "interfaces left over from the killed instance: " + str(stale)
    finally:
        accel_pppd_process.end(
            thread,
            control,
            accel_cmd,
            pytestconfig.getoption("accel_pppd_max_finish_time"),
        )
