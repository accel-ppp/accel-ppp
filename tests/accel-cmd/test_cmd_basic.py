import pytest
from common import process


def test_accel_cmd_version(accel_cmd):
    (exit, out, err) = process.run([accel_cmd, "--version"])

    # test that accel-cmd --version exits with code 0, prints
    # nothing to stdout and prints to stdout
    assert exit == 0 and err == "" and "accel-cmd " in out and len(out.split(" ")) == 2


def test_accel_cmd_non_existent_host(accel_cmd):
    (exit, out, err) = process.run([accel_cmd, "-Hnon-existent-host", "--verbose"])

    # test that accel-cmd (tried to connecto to non-existent host) exits with code != 0,
    # prints nothing to stdout and prints an error to stderr
    assert exit != 0 and out == "" and err != ""


def test_accel_cmd_mcast_host(accel_cmd):
    (exit, out, err) = process.run([accel_cmd, "-H225.0.0.1"])

    # test that accel-cmd (tried to connecto to mcast host) exits with code != 0,
    # prints nothing to stdout and prints an error to stderr
    assert exit != 0 and out == "" and err != ""
