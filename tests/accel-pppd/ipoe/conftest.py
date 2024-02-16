import pytest
from common import dhclient_process
import tempfile, os

# dhclient executable file name
@pytest.fixture()
def dhclient(pytestconfig):
    return pytestconfig.getoption("dhclient")


# pppd configuration as command line args (might be redefined by specific test)
# "-d" (do not daemonize) must be a part of the args
@pytest.fixture()
def dhclient_args():
    # test setup:
    #lease_file = tempfile.NamedTemporaryFile(delete=True)
    #lease_file_name = lease_file.name
    #lease_file.close()  # just create, close and delete

    # test execution:
    yield ["-d", "-4", "--no-pid", "-lf", "/dev/null"]

    # test teardown:
    #os.unlink(lease_file_name)


# setup and teardown for tests that required running dhclient (after accel-pppd)
@pytest.fixture()
def dhclient_instance(accel_pppd_instance, veth_pair_netns, dhclient, dhclient_args):
    # test setup:
    print("dhclient_instance: accel_pppd_instance = " + str(accel_pppd_instance))
    is_started, dhclient_thread, dhclient_control = dhclient_process.start(
        veth_pair_netns["netns"],
        dhclient,
        dhclient_args,
    )

    # test execution:
    yield {
        "is_started": is_started,
        "dhclient_thread": dhclient_thread,
        "dhclient_control": dhclient_control,
    }

    # test teardown:
    dhclient_process.end(dhclient_thread, dhclient_control)
