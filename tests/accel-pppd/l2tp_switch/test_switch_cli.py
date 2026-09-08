import pytest
from common import process


@pytest.mark.l2tp_switch
def test_l2tp_switch_add_unknown_target(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run(
        [accel_cmd, "l2tp switch add Calling-Number exact 472913 acme"]
    )
    # accel-cmd's own exit code only reflects local/connection errors, not
    # whether the remote CLI command itself failed -- same convention as
    # e.g. test_pppoe_session_wo_auth.py's "# accel-cmd fails" cases. The
    # daemon reports failure by appending "command failed" to the response
    # text instead.
    assert exit == 0
    assert "failed" in out


@pytest.mark.l2tp_switch
class TestWithTarget:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_l2tp_switch_add_del(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch add Calling-Number exact 472913 acme"]
        )
        assert exit == 0
        assert "failed" not in out

        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch del Calling-Number exact 472913"]
        )
        assert exit == 0
        assert "failed" not in out

        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch del Calling-Number exact 472913"]
        )
        assert exit == 0
        assert "failed" in out  # already removed

    def test_l2tp_switch_add_duplicate_rejected(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch add Calling-Number exact 472913 acme"]
        )
        assert exit == 0
        assert "failed" not in out

        # same attr/mode/value again, even naming a valid target --
        # l2tp_switch_rule_add()'s own overlap check (rules_overlap(),
        # l2tp_switch_conf.c) must reject this, not silently overwrite it
        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch add Calling-Number exact 472913 acme"]
        )
        assert exit == 0
        assert "failed" in out

    def test_l2tp_switch_add_overlapping_prefix_rejected(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch add Proxy-Authen-Name prefix downstream- acme"]
        )
        assert exit == 0
        assert "failed" not in out

        # "downstream-54546" starts with "downstream-" -- ambiguous with
        # the prefix rule just added, must be rejected even though this
        # one is an exact rule, not another prefix.
        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch add Proxy-Authen-Name exact downstream-54546 acme"]
        )
        assert exit == 0
        assert "failed" in out
