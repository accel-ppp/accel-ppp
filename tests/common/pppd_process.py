from subprocess import Popen, PIPE
from threading import Thread


def pppd_thread_func(pppd_control):
    process = pppd_control["process"]
    print("pppd_thread_func: before communicate")
    (out, err) = process.communicate()
    print("pppd_thread_func: after communicate out=" + str(out) + " err=" + str(err))
    process.wait()
    print("pppd_thread_func: after wait")


def start(netns, pppd, args):
    print("pppd_start: begin")
    print("pppd_start: args=" + str(args))
    pppd_process = Popen(
        ["ip", "netns", "exec", netns] + [pppd] + args, stdout=PIPE, stderr=PIPE
    )
    print("pppd_start: pppd_process=" + str(pppd_process))
    pppd_control = {"process": pppd_process}
    pppd_thread = Thread(
        target=pppd_thread_func,
        args=[pppd_control],
    )
    pppd_thread.start()

    is_started = True if pppd_process.poll() is None else False

    return (is_started, pppd_thread, pppd_control)


def end(pppd_thread, pppd_control):
    print("pppd_end: begin")
    if pppd_control["process"].poll() is not None:  # already terminated
        print("pppd_end: already terminated. nothing to do")
        pppd_thread.join()
        return

    print("pppd_end: kill process: " + str(pppd_control["process"]))
    pppd_control["process"].kill()  # kill -9
    pppd_thread.join()  # wait until thread is finished
    print("pppd_end: end")
