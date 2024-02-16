from subprocess import Popen, PIPE
from common import process
from threading import Thread
import time


def accel_pppd_thread_func(accel_pppd_control):
    process = accel_pppd_control["process"]
    print("accel_pppd_thread_func: before communicate")
    (out, err) = process.communicate()
    print(
        "accel_pppd_thread_func: after communicate out=" + str(out) + " err=" + str(err)
    )
    process.wait()
    print("accel_pppd_thread_func: after wait")


def start(accel_pppd, args, accel_cmd, max_wait_time):
    print("accel_pppd_start: begin")
    accel_pppd_process = Popen([accel_pppd] + args, stdout=PIPE, stderr=PIPE)
    accel_pppd_control = {"process": accel_pppd_process}
    accel_pppd_thread = Thread(
        target=accel_pppd_thread_func,
        args=[accel_pppd_control],
    )
    accel_pppd_thread.start()

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
        (exit, out, err) = process.run([accel_cmd, "show version"])
        if exit != 0:  # does not reply
            time.sleep(0.1)
            sleep_time += 0.1
        else:  # replied
            print("accel_pppd_start: 'show version' replied")
            is_started = True
            break

    return (is_started, accel_pppd_thread, accel_pppd_control)


def end(accel_pppd_thread, accel_pppd_control, accel_cmd, max_wait_time):
    print("accel_pppd_end: begin")
    if accel_pppd_control["process"].poll() is not None: # terminated
        print("accel_pppd_end: already terminated. nothing to do")
        accel_pppd_thread.join() 
        return

    process.run(
        [accel_cmd, "shutdown hard"]
    )  # send shutdown hard command (in coverage mode it helps saving coverage data)
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
        print("accel_pppd_end: kill process: " + str(accel_pppd_control["process"]))
        accel_pppd_control["process"].kill()  # kill -9 if 'shutdown hard' didn't help

    accel_pppd_thread.join()  # wait until thread is finished
    print("accel_pppd_end: end")
