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
    peer_thread = Thread(target=peer_thread_func, args=[peer_control])
    peer_thread.start()

    return (peer_thread, peer_control)


def wait(peer_thread, peer_control, timeout):
    peer_thread.join(timeout)
    return peer_control["process"].returncode, peer_control["out"], peer_control["err"]
