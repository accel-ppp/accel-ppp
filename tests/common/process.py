from subprocess import Popen, PIPE

def run(command):
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    (out, err) = process.communicate()
    exit_code = process.wait()
    return (exit_code, out.decode("utf-8"), err.decode("utf-8"))