import pytest
from common import process


def test_l2tp_switch_show_empty(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

    assert exit == 0
    assert "targets:" in out


class TestWithTarget:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    attr=Calling-Number
    target=acme,203.0.113.50,1701,targetsecret
    line=472913,acme
    """

    def test_l2tp_switch_show_target(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


class TestDuplicateLine:
    """A line= value must not appear twice, even pointing at different
    targets -- spec section 11's fatal config-load error, not silent
    last-wins."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    line=472913,acme
    line=472913,other
    """

    def test_duplicate_line_value_rejected(self, accel_pppd_instance):
        # l2tp_switch_conf_load() returning -1 makes l2tp_init() call
        # log_emerg()+_exit(EXIT_FAILURE) before the daemon ever becomes
        # ready -- accel_pppd_instance (the shared fixture) should report
        # this as a failed start, not a successful one.
        assert accel_pppd_instance is False


class TestSelfLoopTarget:
    """A target whose peer-addr equals this host's own [l2tp] bind
    address is a tunnel-to-itself misconfiguration -- also a fatal
    config-load error (spec section 11)."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=loopback,127.0.0.1,1701,targetsecret
    line=472913,loopback
    """

    @pytest.fixture()
    def accel_pppd_config(self, l2tp_switch_config):
        # Overrides the module-level fixture (Task 1) to add an explicit
        # [l2tp] bind= -- without one, l2tp_conf_get_bind_addr() returns
        # INADDR_ANY, which validate_no_self_loop() deliberately treats as
        # "skip the check" (Task 1 Step 1), so this test would otherwise
        # never actually exercise the rejection it's testing for.
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
    bind=127.0.0.1

    """
            + l2tp_switch_config
        )

    def test_self_loop_target_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False
