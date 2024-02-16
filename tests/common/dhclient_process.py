from subprocess import Popen, PIPE
from threading import Thread


def dhclient_thread_func(dhclient_control):
    process = dhclient_control["process"]
    print("dhclient_thread_func: before communicate")
    (out, err) = process.communicate()
    print(
        "dhclient_thread_func: after communicate out=" + str(out) + " err=" + str(err)
    )
    process.wait()
    print("dhclient_thread_func: after wait")


def start(netns, dhclient, args):
    print("dhclient_start: begin")
    print("dhclient_start: args=" + str(args))
    dhclient_process = Popen(
        ["ip", "netns", "exec", netns] + [dhclient] + args, stdout=PIPE, stderr=PIPE
    )
    print("dhclient_start: dhclient_process=" + str(dhclient_process))
    dhclient_control = {"process": dhclient_process}
    dhclient_thread = Thread(
        target=dhclient_thread_func,
        args=[dhclient_control],
    )
    dhclient_thread.start()

    is_started = True if dhclient_process.poll() is None else False

    return (is_started, dhclient_thread, dhclient_control)


def end(dhclient_thread, dhclient_control):
    print("dhclient_end: begin")
    if dhclient_control["process"].poll() is not None:  # already terminated
        print("dhclient_end: already terminated. nothing to do")
        dhclient_thread.join()
        return

    print("dhclient_end: kill process: " + str(dhclient_control["process"]))
    dhclient_control["process"].kill()  # kill -9
    dhclient_thread.join()  # wait until thread is finished
    print("dhclient_end: end")
