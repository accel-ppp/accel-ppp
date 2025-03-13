import pytest, subprocess, re
from common import pppd_process
from packaging.version import Version

# pppd executable file name
@pytest.fixture()
def pppd(pytestconfig):
    return pytestconfig.getoption("pppd")


# pppd configuration as string (should be redefined by specific test)
# all configs should contain "nodetach" option
@pytest.fixture()
def pppd_config():
    return ""

# determines which plugin is required - pppoe.so (pppd 2.5.0+) or rp-pppoe.so (pppd <2.5.0)
def pppd_plugin_so(pppd):
    command = [pppd, "--version"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pppd_version = Version(re.search(r'\d+\.\d+\.\d+', result.stdout + result.stderr).group())
    ref_version = Version("2.5.0")
    if pppd_version >= ref_version:
        return "pppoe.so"
    else:
        return "rp-pppoe.so"

# pppd configuration as command line args
@pytest.fixture()
def pppd_args(pppd_config, pppd):
    return ("plugin " + pppd_plugin_so(pppd) + "\n" + pppd_config).split()


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
