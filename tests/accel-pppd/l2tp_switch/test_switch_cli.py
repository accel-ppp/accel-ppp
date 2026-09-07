import pytest
from common import process


def test_l2tp_switch_add_unknown_target(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch add 472913 acme"])
    # accel-cmd's own exit code only reflects local/connection errors, not
    # whether the remote CLI command itself failed -- same convention as
    # e.g. test_pppoe_session_wo_auth.py's "# accel-cmd fails" cases. The
    # daemon reports failure by appending "command failed" to the response
    # text instead.
    assert exit == 0
    assert "failed" in out


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
            [accel_cmd, "l2tp switch add 472913 acme"]
        )
        assert exit == 0
        assert "failed" not in out

        (exit, out, err) = process.run([accel_cmd, "l2tp switch del 472913"])
        assert exit == 0
        assert "failed" not in out

        (exit, out, err) = process.run([accel_cmd, "l2tp switch del 472913"])
        assert exit == 0
        assert "failed" in out  # already removed

    def test_l2tp_switch_add_duplicate_rejected(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch add 472913 acme"])
        assert exit == 0
        assert "failed" not in out

        # same value again, even naming a valid target -- l2tp_switch_line_add()'s
        # own line_find() check (Task 1) must reject this, not silently overwrite it
        (exit, out, err) = process.run([accel_cmd, "l2tp switch add 472913 acme"])
        assert exit == 0
        assert "failed" in out
