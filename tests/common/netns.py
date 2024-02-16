from common import process

# creates netns and returns netns name. if ok return 0
def create(netns_name):
    netns, out, err = process.run(["ip", "netns", "add", netns_name])
    print("netns.create: exit=%d out=%s err=%s" % (netns, out, err))

    return netns


# deletes netns. if ok return 0
def delete(netns_name):
    netns, out, err = process.run(["ip", "netns", "delete", netns_name])
    print("netns.delete: exit=%d out=%s err=%s" % (netns, out, err))

    return netns


# execute command in netns using process.run
# if netns_name is None, then execute in global rt
def exec(netns_name, command):
    if netns_name is None:
        exit, out, err = process.run(command)
    else:
        exit, out, err = process.run(["ip", "netns", "exec", netns_name] + command)

    print("netns.exec: netns=%s command=%s :: exit=%d out=%s err=%s" % (netns_name, str(command), exit, out, err))

    return (exit, out, err)
