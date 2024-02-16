import pytest
import os

# test that ipoe kernel module is loaded
@pytest.mark.dependency(name = 'ipoe_driver_loaded', scope = 'session')
@pytest.mark.ipoe_driver
def test_ipoe_kernel_module_loaded():
    assert os.path.isdir("/sys/module/ipoe")