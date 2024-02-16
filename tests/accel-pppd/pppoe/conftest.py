import pytest
from common import pppd_process

# pppd executable file name
@pytest.fixture()
def pppd(pytestconfig):
    return pytestconfig.getoption("pppd")


# pppd configuration as string (should be redefined by specific test)
# all configs should contain "nodetach" option
@pytest.fixture()
def pppd_config():
    return ""


# pppd configuration as command line args
@pytest.fixture()
def pppd_args(pppd_config):
    return pppd_config.split()


# setup and teardown for tests that required running pppd (after accel-pppd)
@pytest.fixture()
def pppd_instance(accel_pppd_instance, veth_pair_netns, pppd, pppd_args):
    # test setup:
    print("pppd_instance: accel_pppd_instance = " + str(accel_pppd_instance))
    is_started, pppd_thread, pppd_control = pppd_process.start(
        veth_pair_netns["netns"],
        pppd,
        pppd_args,
    )

    # test execution:
    yield {
        "is_started": is_started,
        "pppd_thread": pppd_thread,
        "pppd_control": pppd_control,
    }

    # test teardown:
    pppd_process.end(pppd_thread, pppd_control)
