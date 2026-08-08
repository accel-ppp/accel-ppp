from common import process
import os
import signal
import time


# (ifindex, name) of every ipoe session interface currently in the kernel.
# Matched by name rather than by 'ip link show type ipoe' so that the helper
# keeps working with a module that does not register rtnl_link_ops.
def list_ipoe():
    (exit_code, out, err) = process.run(["ip", "-o", "link", "show"])
    assert exit_code == 0, "ip link show failed: " + err

    ifaces = []
    for line in out.splitlines():
        fields = line.split(":")
        if len(fields) < 2:
            continue
        try:
            ifindex = int(fields[0].strip())
        except ValueError:
            continue
        name = fields[1].strip().split("@")[0]
        if name.startswith("ipoe"):
            ifaces.append((ifindex, name))

    return ifaces


# pids of the running accel-pppd processes
def accel_pppd_pids():
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/" + entry + "/comm") as comm:
                if comm.read().strip() == "accel-pppd":
                    pids.append(int(entry))
        except OSError:  # process is gone, or not ours to look at
            pass

    return pids


# SIGKILL every accel-pppd and wait until they are really gone.
# Returns the number of processes that were killed.
def kill_accel_pppd(max_wait_time=10.0):
    pids = accel_pppd_pids()
    for pid in pids:
        print("kill_accel_pppd: SIGKILL to pid " + str(pid))
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    sleep_time = 0.0
    while sleep_time < max_wait_time:
        if not accel_pppd_pids():
            print("kill_accel_pppd: gone in (sec): " + str(sleep_time))
            break
        time.sleep(0.1)
        sleep_time += 0.1

    return len(pids)


# wait until accel-pppd reports an active ipoe session on the given interface
def wait_for_session(accel_cmd, called_sid, max_wait_time=10.0):
    sleep_time = 0.0
    out = ""
    while sleep_time < max_wait_time:
        (exit_code, out, err) = process.run(
            [accel_cmd, "show sessions called-sid,ip,state"]
        )
        assert exit_code == 0, "accel-cmd failed: " + err
        if called_sid in out and "192.0.2." in out and "active" in out:
            print("wait_for_session: session found in (sec): " + str(sleep_time))
            return True
        time.sleep(0.1)
        sleep_time += 0.1

    print("wait_for_session: last accel-cmd out: " + out)
    return False
