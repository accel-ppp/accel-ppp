from subprocess import Popen, PIPE, TimeoutExpired
from common import hang_diagnostics, process
from threading import Thread
import time
import warnings

# upper bound for one accel-cmd call made by this module (accel-cmd itself
# waits forever without -t)
CLI_TIMEOUT = 10.0
THREAD_JOIN_TIMEOUT = 10.0


def accel_pppd_thread_func(accel_pppd_control):
    process = accel_pppd_control["process"]
    print("accel_pppd_thread_func: before communicate")
    (out, err) = process.communicate()
    accel_pppd_control["out"] = out
    accel_pppd_control["err"] = err
    print(
        "accel_pppd_thread_func: after communicate out=" + str(out) + " err=" + str(err)
    )
    process.wait()
    print("accel_pppd_thread_func: after wait")


def start(accel_pppd, args, accel_cmd, max_wait_time, cli_port=None, env=None):
    print("accel_pppd_start: begin")
    accel_pppd_process = Popen([accel_pppd] + args, stdout=PIPE, stderr=PIPE, env=env)
    accel_pppd_control = {"process": accel_pppd_process}
    accel_pppd_thread = Thread(
        target=accel_pppd_thread_func,
        args=[accel_pppd_control],
        daemon=True,  # a stuck pipe reader must not keep pytest from exiting
    )
    accel_pppd_thread.start()

    # accel-cmd defaults to port 2001; cli_port is needed when [cli] tcp=
    # uses another port, e.g. for a second simultaneous instance.
    check_cmd = [accel_cmd]
    if cli_port is not None:
        check_cmd += ["-p", str(cli_port)]
    check_cmd += ["show version"]

    # wait until accel-pppd replies to 'show version'
    # accel-pppd needs some time to be accessible
    sleep_time = 0.0
    is_started = False
    while sleep_time < max_wait_time:
        if accel_pppd_process.poll() is not None:  # process is terminated
            print(
                "accel_pppd_start: terminated during 'show version' polling in (sec): "
                + str(sleep_time)
            )
            is_started = False
            break
        try:
            (exit, out, err) = process.run(check_cmd, timeout=CLI_TIMEOUT)
        except TimeoutExpired:  # accepted the connection but never replied
            exit = -1
        if exit != 0:  # does not reply
            time.sleep(0.1)
            sleep_time += 0.1
        else:  # replied
            print("accel_pppd_start: 'show version' replied")
            is_started = True
            break

    accel_pppd_control["started"] = is_started
    return (is_started, accel_pppd_thread, accel_pppd_control)


def _join_reader(accel_pppd_thread, accel_pppd_control):
    # the reader thread only ends when the pipes close; a leftover child
    # holding them open must not hang the test run
    accel_pppd_thread.join(THREAD_JOIN_TIMEOUT)
    if accel_pppd_thread.is_alive():
        accel_pppd_control["process"].kill()
        accel_pppd_thread.join(THREAD_JOIN_TIMEOUT)
        raise RuntimeError("accel-pppd output reader did not finish after kill")


# Known product bug, tracked separately: log_syslog's syslog_ctx.tpd is NULL
# during shutdown, so do_log() -> triton_context_call() dereferences a null
# triton context. UBSAN (-fno-sanitize-recover) turns it into exit status 1.
# TEMPORARY, remove once the separate fix lands. Only an exit whose stderr
# holds exactly this runtime error (and no other sanitizer report) is waived.
_KNOWN_SHUTDOWN_NULL_CTX = (
    "runtime error: member access within null pointer of type "
    "'struct _triton_context_t'"
)


def _is_known_shutdown_null_ctx_tsan(text):
    # The same crash under TSAN: the SIGSEGV handler (sigsegv -> __core_restart
    # -> close_all_fd) runs inside the faulting thread, and TSAN reports its
    # malloc as a signal-unsafe call. Exactly one report, with the crash stack.
    return (
        text.count("WARNING: ThreadSanitizer:") == 1
        and "signal-unsafe call inside of a signal" in text
        and " sigsegv " in text
        and " triton_context_call " in text
        and " queue_log " in text
        and " do_log " in text
    )


def _is_known_shutdown_null_ctx(err):
    text = err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err)
    if _is_known_shutdown_null_ctx_tsan(text):
        return True
    reports = text.count("runtime error:")
    return (
        reports == 1
        and _KNOWN_SHUTDOWN_NULL_CTX in text
        and " in triton_context_call " in text
        and " in do_log " in text
        and "Sanitizer" not in text
    )


def exit_problem(accel_pppd_control):
    """Describes an unclean accel-pppd exit, or returns None if it was fine.

    Sanitizers (ASAN/LSan/UBSAN/TSAN) report errors found at exit through a
    non-zero exit status or an abort, so anything but a plain exit(0) counts.
    A daemon the harness had to kill is reported separately by end().
    """
    rc = accel_pppd_control.get("returncode")
    if rc is None or rc == 0:
        return None
    if rc < 0:
        return "accel-pppd was killed by signal " + str(-rc)
    return "accel-pppd exited with status " + str(rc)


def end(
    accel_pppd_thread,
    accel_pppd_control,
    accel_cmd,
    max_wait_time,
    cli_port=None,
    check_exit=False,
):
    """Stops accel-pppd. Records accel_pppd_control["returncode"] and
    ["killed"] (True if the harness had to SIGKILL it).

    With check_exit=True an unclean exit (see exit_problem) raises
    AssertionError, after everything is cleaned up. A daemon the harness had
    to kill only produces a warning: its SIGKILL status says nothing.
    """
    print("accel_pppd_end: begin")
    accel_pppd_control["killed"] = False
    if accel_pppd_control["process"].poll() is not None: # terminated
        print("accel_pppd_end: already terminated. nothing to do")
        _join_reader(accel_pppd_thread, accel_pppd_control)
        _finish(accel_pppd_control, check_exit)
        return

    shutdown_cmd = [accel_cmd]
    if cli_port is not None:
        shutdown_cmd += ["-p", str(cli_port)]
    shutdown_cmd += ["shutdown hard"]
    try:
        process.run(
            shutdown_cmd, timeout=CLI_TIMEOUT
        )  # send shutdown hard command (in coverage mode it helps saving coverage data)
    except TimeoutExpired:
        print("accel_pppd_end: 'shutdown hard' got no reply")
    print("accel_pppd_end: after shutdown hard")

    # wait until accel-pppd is finished
    sleep_time = 0.0
    is_finished = False
    while sleep_time < max_wait_time:
        if accel_pppd_control["process"].poll() is None:  # not terminated yet
            time.sleep(0.01)
            sleep_time += 0.01
            # print("accel_pppd_end: sleep 0.01")
        else:
            is_finished = True
            print(
                "accel_pppd_end: finished via shutdown hard in (sec): "
                + str(sleep_time)
            )
            break

    # accel-pppd is still alive. kill it
    if not is_finished:
        hang_diagnostics.dump(
            accel_pppd_control["process"],
            accel_cmd,
            cli_port,
            f"still running {max_wait_time}s after 'shutdown hard'",
        )
        print("accel_pppd_end: kill process: " + str(accel_pppd_control["process"]))
        accel_pppd_control["killed"] = True
        accel_pppd_control["process"].kill()  # kill -9 if 'shutdown hard' didn't help

    _join_reader(accel_pppd_thread, accel_pppd_control)
    print("accel_pppd_end: end")
    _finish(accel_pppd_control, check_exit)


def _finish(accel_pppd_control, check_exit):
    accel_pppd_control["returncode"] = accel_pppd_control["process"].returncode
    print("accel_pppd_end: returncode=" + str(accel_pppd_control["returncode"]))
    if not check_exit:
        return
    if accel_pppd_control["killed"]:
        # SIGKILL's status says nothing about the daemon's own exit. This is
        # not routine-clean either (e.g. 'shutdown hard' waits for the
        # retransmission timeout of a tunnel to an unreachable peer), so say so.
        warnings.warn(
            "accel-pppd did not exit after 'shutdown hard' and was killed; "
            "exit status not checked"
        )
        return
    if not accel_pppd_control.get("started", True):
        # the daemon died during startup (e.g. a rejected config, which the
        # tests provoke on purpose); the caller sees that via is_started
        return
    problem = exit_problem(accel_pppd_control)
    if problem and _is_known_shutdown_null_ctx(accel_pppd_control.get("err", b"")):
        warnings.warn(
            "waived known shutdown bug (null syslog_ctx.tpd in do_log -> "
            "triton_context_call); separate fix pending: " + problem
        )
        return
    if problem:
        hang_diagnostics.dump_logs(accel_pppd_control["process"], problem)
    assert problem is None, problem + " (sanitizer report at exit? see output above)"
