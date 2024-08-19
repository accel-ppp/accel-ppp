import pytest
from common import process


def test_accel_pppd_version(accel_pppd):
    (exit, out, err) = process.run([accel_pppd, "--version"])

    # test that accel-pppd --version exits with code 0, prints
    # nothing to stdout and prints to stdout
    assert exit == 0 and err == "" and "accel-ppp " in out and len(out.split(" ")) == 2


@pytest.fixture()
def accel_pppd_config():
    return """
    [modules]
    log_file
    log_syslog
    log_tcp
    #log_pgsql

    pptp
    l2tp
    sstp
    pppoe
    ipoe

    auth_mschap_v2
    auth_mschap_v1
    auth_chap_md5
    auth_pap

    radius
    chap-secrets

    ippool

    pppd_compat
    shaper
    #net-snmp
    logwtmp
    connlimit

    ipv6_nd
    ipv6_dhcp
    ipv6pool

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [pppoe]

    [client-ip-range]
    10.0.0.0/8

    [radius]
    """


# load all modules and check that accel-pppd replies to 'show stat' command
def test_load_all_modules(accel_pppd_instance, accel_cmd):

    # test that accel-pppd started successfully
    assert accel_pppd_instance

    (exit_sh_stat, out_sh_stat, err_sh_stat) = process.run([accel_cmd, "show stat"])

    # test that 'show stat' has no errors and contains 'uptime'
    assert (
        exit_sh_stat == 0
        and len(out_sh_stat) > 1
        and err_sh_stat == ""
        and "uptime" in out_sh_stat
    )
