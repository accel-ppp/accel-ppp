import pytest
from common import process

pytestmark = pytest.mark.xdist_group("fixed-port")


@pytest.mark.l2tp_switch
def test_l2tp_switch_add_unknown_target(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run(
        [accel_cmd, "l2tp switch add Calling-Number exact 472913 acme"]
    )
    # accel-cmd exits 0 even when the command fails; the failure is in the
    # response text.
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

        # same rule again must be rejected, not overwrite the first
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

        # "downstream-54546" falls under the prefix rule just added
        (exit, out, err) = process.run(
            [accel_cmd, "l2tp switch add Proxy-Authen-Name exact downstream-54546 acme"]
        )
        assert exit == 0
        assert "failed" in out
