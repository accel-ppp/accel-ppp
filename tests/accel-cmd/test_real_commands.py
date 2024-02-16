import pytest
from common import process


@pytest.fixture()
def accel_pppd_config():
    return """
    [modules]

    [log]
    log-debug=/dev/stdout
    level=5

    [cli]
    tcp=127.0.0.1:2001
    """


# test accel-cmd command with started accel-pppd
def test_accel_cmd_commands(accel_pppd_instance, accel_cmd):

    # test that accel-pppd started successfully
    assert accel_pppd_instance

    (exit_sh_stat, out_sh_stat, err_sh_stat) = process.run([accel_cmd, "show stat"])

    # test that 'show stat' has no errors and contains 'uptime'
    assert (
        exit_sh_stat == 0
        and len(out_sh_stat) > 0
        and err_sh_stat == ""
        and "uptime" in out_sh_stat
    )

    (exit_sh_ses, out_sh_ses, err_sh_ses) = process.run(
        [accel_cmd, "show sessions sid,uptime"]
    )
    # test that 'show sessions' has no errors and contains 'sid'
    assert (
        exit_sh_ses == 0
        and len(out_sh_ses) > 0
        and err_sh_ses == ""
        and "sid" in out_sh_ses
    )

    (exit_help, out_help, err_help) = process.run([accel_cmd, "help"])
    # test that 'help' has no errors and contains 'show stat'
    assert (
        exit_help == 0
        and len(out_help) > 0
        and err_help == ""
        and "show stat" in out_help
    )
