from subprocess import Popen, PIPE, TimeoutExpired

# Timeout used by run() when the caller passes none. None waits forever (the
# historic behaviour); a test package can set a bound for all its callers.
default_timeout = None


def run(command, timeout=None):
    """Runs `command` and returns (exit_code, stdout, stderr).

    With `timeout` (seconds, default: default_timeout) a command that does not finish in time is
    killed and subprocess.TimeoutExpired is raised, so a hung child (e.g.
    accel-cmd without -t) fails the caller instead of blocking forever.
    Without it the call waits indefinitely, as before.
    """
    if timeout is None:
        timeout = default_timeout
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    try:
        (out, err) = process.communicate(timeout=timeout)
    except TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    exit_code = process.wait()
    return (exit_code, out.decode("utf-8"), err.decode("utf-8"))
