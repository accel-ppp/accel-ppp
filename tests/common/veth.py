from common import process, netns, vlan, iface
import time
import math

# creates veth pair, optionally with fixed hardware addresses. if ok returns 0
def create_pair(name_a, name_b, mac_a=None, mac_b=None):
    command = ["ip", "link", "add", name_a]
    if mac_a:
        command += ["address", mac_a]
    command += ["type", "veth", "peer", "name", name_b]
    if mac_b:
        command += ["address", mac_b]

    veth, out, err = process.run(command)
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

    # fixed addresses: a veth pair created without them gets random ones, which
    # systemd-udevd may replace right after creation (MACAddressPolicy in its
    # .link rules). accel-pppd reads the address of the interface it serves once
    # at startup, so when udev wins that race the daemon advertises an address
    # the interface no longer has and the session never passes a frame.
    # See https://github.com/accel-ppp/accel-ppp/issues/363
    num = int(name)
    mac = "02:00:%02x:%02x:%02x:" % ((num >> 16) & 0xFF, (num >> 8) & 0xFF, num & 0xFF)
    pair_status = create_pair(veth_a, veth_b, mac + "0a", mac + "0b")
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
