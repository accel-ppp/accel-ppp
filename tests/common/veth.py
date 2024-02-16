from common import process, netns, vlan, iface
import time
import math

# creates veth pair. if ok returns 0
def create_pair(name_a, name_b):
    veth, out, err = process.run(
        ["ip", "link", "add", name_a, "type", "veth", "peer", "name", name_b]
    )
    print("veth.create: exit=%d out=%s err=%s" % (veth, out, err))

    return veth


# put veth to netns. if ok returns 0
def assign_netns(veth, netns):
    veth, out, err = process.run(["ip", "link", "set", veth, "netns", netns])
    print("veth.assign_netns: exit=%d out=%s err=%s" % (veth, out, err))

    return veth


# creates netns, creates veth pair and place second link to netns
# creates vlans over veth interfaces according to veth_pair_vlans_config
# return dict with 'netns', 'veth_a', 'veth_b'
def create_veth_pair_netns(veth_pair_vlans_config):

    name = str(math.floor(time.time() * 1000) % 1000000)
    netns_name = "N" + name
    netns_status = netns.create(netns_name)
    print("create_veth_pair_netns: netns_status=%d" % netns_status)

    veth_a = "A" + name
    veth_b = "B" + name
    pair_status = create_pair(veth_a, veth_b)
    print("create_veth_pair_netns: pair_status=%d" % pair_status)

    iface.up(veth_a, None)

    assign_status = assign_netns(veth_b, netns_name)
    print("create_veth_pair_netns: assign_status=%d" % assign_status)

    iface.up(veth_b, netns_name)

    vlans_a = veth_pair_vlans_config["vlans_a"]
    for vlan_num in vlans_a:
        vlan.create(veth_a, vlan_num, None)
        iface.up(veth_a + "." + str(vlan_num), None)

    vlans_b = veth_pair_vlans_config["vlans_b"]
    for vlan_num in vlans_b:
        vlan.create(veth_b, vlan_num, netns_name)
        iface.up(veth_b + "." + str(vlan_num), netns_name)

    return {
        "netns": netns_name,
        "veth_a": veth_a,
        "veth_b": veth_b,
        "vlans_a": vlans_a,
        "vlans_b": vlans_b,
    }


# deletes veth pair and netns created by create_veth_pair_netns
def delete_veth_pair_netns(veth_pair_netns):

    vlans_a = veth_pair_netns["vlans_a"]
    veth_a = veth_pair_netns["veth_a"]
    vlans_b = veth_pair_netns["vlans_b"]
    veth_b = veth_pair_netns["veth_b"]
    netns_name = veth_pair_netns["netns"]

    # remove vlans on top of veth interface
    for vlan_num in vlans_a:
        iface.delete(veth_a + "." + str(vlan_num), None)
    for vlan_num in vlans_b:
        iface.delete(veth_b + "." + str(vlan_num), netns_name)

    veth_status = iface.delete(veth_a, None)
    print("delete_veth_pair_netns: veth_status=%d" % veth_status)

    netns_status = netns.delete(netns_name)
    print("delete_veth_pair_netns: netns_status=%d" % netns_status)
