import pytest
from common import process


@pytest.fixture()
def accel_pppd_config():
    return """
    [modules]
    radius
    pppoe

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [radius]

    [pppoe]
    """


# test pcre-related negative cases
def test_pcre_negative_cases(accel_pppd_instance, accel_cmd):

    # test that accel-pppd started successfully
    assert accel_pppd_instance

    (exit_sh_sess, out_sh_sess, err_sh_sess) = process.run([accel_cmd, "show sessions match username 00("])
    # test that 'show sessions' with invalid regexp reports the issue and error position
    assert (
        exit_sh_sess == 0
        and len(out_sh_sess) > 0
        and err_sh_sess == ""
        and "match: " in out_sh_sess
        and "at 3" in out_sh_sess
    )


    (exit_iface_add, out_iface_add, err_iface_add) = process.run([accel_cmd, "pppoe interface add re:000("])
    # test that 'pppoe interface add' with invalid regexp reports the issue and error position
    assert (
        exit_iface_add == 0
        and len(out_iface_add) > 0
        and err_iface_add == ""
        and "pppoe: " in out_iface_add
        and "at 4" in out_iface_add
    )

    (exit_term, out_term, err_term) = process.run([accel_cmd, "terminate match username 00("])
    # test that 'terminate' with invalid regexp reports the issue and error position
    assert (
        exit_term == 0
        and len(out_term) > 0
        and err_term == ""
        and "match: " in out_term
        and "at 3" in out_term
    )
