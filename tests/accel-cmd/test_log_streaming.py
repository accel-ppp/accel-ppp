from subprocess import PIPE, Popen, TimeoutExpired

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
    log-history=10
    verbose=2
    """


def test_log_history_command(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit_hist, out_hist, err_hist) = process.run([accel_cmd, "log history"])
    assert exit_hist == 0 and "log history: 10" in out_hist and err_hist == ""

    (exit_set, out_set, err_set) = process.run([accel_cmd, "log history 5"])
    assert exit_set == 0 and "log history: 5" in out_set and err_set == ""

    (exit_off, out_off, err_off) = process.run([accel_cmd, "log history off"])
    assert exit_off == 0 and "log history: 0" in out_off and err_off == ""


def test_log_show_and_follow(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit_hist, out_hist, err_hist) = process.run([accel_cmd, "log history 10"])
    assert exit_hist == 0 and "log history: 10" in out_hist and err_hist == ""

    (exit_stat, out_stat, err_stat) = process.run([accel_cmd, "show stat"])
    assert exit_stat == 0 and "uptime" in out_stat and err_stat == ""

    (exit_show, out_show, err_show) = process.run([accel_cmd, "log show 5"])
    assert exit_show == 0 and err_show == "" and "show stat" in out_show

    proc = Popen([accel_cmd], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    try:
        out_follow, err_follow = proc.communicate(
            input=b"log follow tail 1\nlog stop\n",
            timeout=5,
        )
    except TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail("accel-cmd log follow did not exit")

    out_follow = out_follow.decode("utf-8")
    err_follow = err_follow.decode("utf-8")

    assert (
        proc.returncode == 0
        and err_follow == ""
        and "log follow: enabled" in out_follow
        and "log follow: disabled" in out_follow
        and "cli:" in out_follow
    )
