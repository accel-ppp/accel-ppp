from common import netns

# up interface. if netns is None, then up in global rt. if ok returns 0
def create(parent_if, vlan, netns_name):
    command = (
        "ip link add link %s name %s.%d type vlan id %d"
        % (parent_if, parent_if, vlan, vlan)
    ).split()

    vlan, out, err = netns.exec(netns_name, command)
    print("vlan.create: exit=%d out=%s err=%s" % (vlan, out, err))

    return vlan
