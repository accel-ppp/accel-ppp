from subprocess import Popen, PIPE
from threading import Thread


def peer_thread_func(peer_control):
    process = peer_control["process"]
    (out, err) = process.communicate()
    peer_control["out"] = out
    peer_control["err"] = err
    process.wait()


def start(peer_bin, args):
    peer_process = Popen([peer_bin] + args, stdout=PIPE, stderr=PIPE, text=True)
    peer_control = {"process": peer_process, "out": "", "err": ""}
    peer_thread = Thread(target=peer_thread_func, args=[peer_control], daemon=True)
    peer_thread.start()

    return (peer_thread, peer_control)


def wait(peer_thread, peer_control, timeout, kill_on_timeout=True):
    """Waits up to `timeout` seconds for the harness to exit.

    A harness that is still running afterwards is killed (so it cannot hang
    the test run) and reports a negative returncode (-SIGKILL), which makes
    the usual `rc == 0` assertion fail. Pass kill_on_timeout=False for a
    harness that is meant to outlive the wait; the returncode is then None.
    """
    peer_thread.join(timeout)
    if kill_on_timeout and peer_thread.is_alive():
        peer_control["process"].kill()
        peer_thread.join(5.0)
    return peer_control["process"].returncode, peer_control["out"], peer_control["err"]
