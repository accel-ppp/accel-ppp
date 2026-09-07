import pytest


@pytest.fixture()
def l2tp_switch_config():
    # should be redefined by specific tests
    return ""


@pytest.fixture()
def accel_pppd_config(l2tp_switch_config):
    return (
        """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [l2tp]
    verbose=1
    secret=testsecret

    """
        + l2tp_switch_config
    )
