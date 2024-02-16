from common import netns

# up interface. if netns is None, then up in global rt. if ok returns 0
def up(iface, netns_name):
    command = ["ip", "link", "set", iface, "up"]
    exit, out, err = netns.exec(netns_name, command)
    print(
        "iface.up: iface=%s netns=%s exit=%d out=%s err=%s"
        % (iface, netns_name, exit, out, err)
    )

    return exit


# delete interface. if netns is None, then up in global rt. if ok returns 0
def delete(iface, netns_name):
    exit, out, err = netns.exec(netns_name, ["ip", "link", "delete", iface])
    print(
        "iface.delete: iface=%s netns=%s exit=%d out=%s err=%s"
        % (iface, netns_name, exit, out, err)
    )

    return exit
