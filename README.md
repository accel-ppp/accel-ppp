ACCEL-PPP
=========

ACCEL-PPP is a high-performance, multi-threaded VPN and broadband access
concentrator for Linux. It has its own userspace PPP implementation, so one
daemon can manage all connections without relying on pppd. The implementation
was developed from scratch rather than as a wrapper around pppd. It uses Linux
kernel interfaces for PPTP, L2TP, and PPPoE data paths, while SSTP is handled in
userspace.


Features
========

* Modular architecture and a multi-threaded I/O core
* PPTP, PPPoE (including TR-101), L2TPv2, SSTP, and IPoE. ACCEL-PPP does not
  provide integrated IPsec for L2TPv2; deploy IPsec separately when required.
* RADIUS authentication and accounting, including Disconnect Messages and
  Change of Authorization (DM/CoA)
* PAP, CHAP-MD5, MS-CHAPv1, and MS-CHAPv2 authentication
* Microsoft Point-to-Point Encryption (MPPE)
* File, syslog, TCP, and optional PostgreSQL logging, including per-session logs
* Extensible authentication sources, including RADIUS and pppd-compatible
  chap-secrets files
* Extensible IP address pools populated by RADIUS, chap-secrets, or static
  configuration
* pppd-compatible ip-up and ip-down scripts
* TBF/HTB shaping and clsact policing
* Telnet and TCP command-line interfaces
* Optional SNMP support as a master agent or AgentX subagent

EAP authentication and PPP compression are not supported.


Requirements
============

Building the daemon requires:

* Linux
* A C compiler and standard build tools
* CMake 3.10 or newer
* OpenSSL development files
* PCRE2 development files

Kernel headers are also required when building the optional PPTP, IPoE, or VLAN
monitoring kernel modules. Optional features require their corresponding
development libraries:

* Net-SNMP for NETSNMP=TRUE
* PostgreSQL client libraries for LOG_PGSQL=TRUE
* Lua for LUA=TRUE or a specific Lua version such as LUA=5.3


Building and installing
=======================

Use an out-of-tree build directory:

    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local
    cmake --build build
    sudo cmake --install build

Useful build options:

* BUILD_PPTP_DRIVER=TRUE builds the PPTP kernel module.
* BUILD_IPOE_DRIVER=TRUE builds the IPoE kernel module.
* BUILD_VLAN_MON_DRIVER=TRUE builds the VLAN monitoring kernel module.
* BUILD_DRIVER_ONLY=TRUE builds only the selected kernel modules.
* KDIR=/path/to/kernel/build sets the kernel build directory.
* RADIUS=FALSE omits RADIUS support.
* SHAPER=FALSE omits the traffic-shaping module.
* NETSNMP=TRUE builds SNMP support.
* LOG_PGSQL=TRUE builds PostgreSQL logging support.

For example, to build the IPoE and VLAN monitoring modules for the running
kernel:

    cmake -S . -B build \
      -DBUILD_IPOE_DRIVER=TRUE \
      -DBUILD_VLAN_MON_DRIVER=TRUE \
      -DKDIR="/usr/src/linux-headers-$(uname -r)"
    cmake --build build


Configuration
=============

The sample configuration is installed as accel-ppp.conf.dist. See
"man 5 accel-ppp.conf" for the complete configuration reference.

Enable or disable functionality in the [modules] section. To authenticate from
a pppd-compatible secrets file, enable chap-secrets instead of radius. RADIUS
may remain compiled in; RADIUS=FALSE is only needed when it should be omitted
from the build. Loading both providers does not provide dependable automatic
fallback from RADIUS to chap-secrets because authentication providers are
consulted in module registration order.

For DM/CoA deployments, configure dae-allowed in the [radius] section to
restrict permitted source addresses.


Built-in shaper
===============

The shaper supports TBF and HTB queueing disciplines and a clsact policer.
Build it with SHAPER=TRUE (the default), then enable shaper in the
configuration's [modules] section.

RADIUS rate attributes accept a single rate or separate downstream/upstream
rates. The default attribute is Filter-Id. Values are in Kbit/s unless
Cisco-style attributes are used:

    Filter-Id=1000
    Filter-Id=2000/3000

The first example sets both directions to 1000 Kbit/s. The second sets the
downstream rate to 2000 Kbit/s and the upstream rate to 3000 Kbit/s.

Set a custom rate attribute with attr. The named attribute must exist in the
RADIUS dictionary:

    [shaper]
    attr=My-Custom-Rate-Attribute

Alternatively, use separate attributes for each direction:

    [shaper]
    attr-down=PPPD-Downstream-Speed
    attr-up=PPPD-Upstream-Speed

For Cisco-style attributes:

    [shaper]
    vendor=Cisco
    attr=Cisco-AVPair

Send input and output attributes to set both directions. In Cisco-style
attributes, input controls upstream traffic and output controls downstream
traffic:

    Cisco-AVPair=lcp:interface-config#1=rate-limit input 2000000 8000 8000 conform-action transmit exceed-action drop
    Cisco-AVPair=lcp:interface-config#1=rate-limit output 2000000 8000 8000 conform-action transmit exceed-action drop

These examples set a 2000 Kbit/s rate and an 8 KB burst in each direction.


Burst configuration
-------------------

For non-Cisco attributes, configure the factors used to calculate bursts from
the rate. down-burst-factor applies to downstream TBF/HTB shaping;
up-burst-factor applies to upstream policing/HTB shaping:

    [shaper]
    down-burst-factor=1.0
    up-burst-factor=10.0


Time ranges
-----------

Time ranges can change rates automatically:

    [shaper]
    time-range=1,1:00-3:00
    time-range=2,3:00-5:00
    time-range=3,5:00-7:00

Prefix a rate with its range ID and supply multiple RADIUS attributes:

    Filter-Id=1000
    Filter-Id=1,2000
    Filter-Id=2,3000
    Filter-Id=3,4000

This sets a default of 1000 Kbit/s and rates of 2000, 3000, and 4000 Kbit/s in
ranges 1, 2, and 3 respectively.

For Cisco-style time ranges, the access-group value is the range ID:

    Cisco-AVPair=lcp:interface-config#1=rate-limit output access-group 1 1000000 8000 8000 conform-action transmit exceed-action drop
    Cisco-AVPair=lcp:interface-config#1=rate-limit input access-group 1 1000000 8000 8000 conform-action transmit exceed-action drop

When using chap-secrets, an optional fifth column can provide rate information
in the same format. Time ranges are not supported in chap-secrets.


SNMP
====

Build SNMP support with NETSNMP=TRUE and enable net-snmp in [modules]. ACCEL-PPP
starts as an AgentX subagent by default, so the Net-SNMP master agent must have
AgentX enabled. Consult the Net-SNMP AgentX documentation when configuring the
master agent. To run ACCEL-PPP as the master agent instead:

    [snmp]
    master=1

Install accel-pppd/extra/net-snmp/ACCEL-PPP-MIB.txt in the local MIB directory.
The file also contains the numerical OIDs used by ACCEL-PPP. Examples:

    # Read statistics and sessions.
    snmpwalk -m +ACCEL-PPP-MIB -v 2c -c local 127.0.0.1 ACCEL-PPP-MIB::accelPPPStat
    snmptable -m +ACCEL-PPP-MIB -v 2c -c local 127.0.0.1 ACCEL-PPP-MIB::sessionsTable

    # Terminate sessions by accounting ID, interface, address, or username.
    snmpset -m +ACCEL-PPP-MIB -v 2c -c local 127.0.0.1 ACCEL-PPP-MIB::termBySID.0 = 0000000000000001
    snmpset -m +ACCEL-PPP-MIB -v 2c -c local 127.0.0.1 ACCEL-PPP-MIB::termByIfName.0 = ppp2
    snmpset -m +ACCEL-PPP-MIB -v 2c -c local 127.0.0.1 ACCEL-PPP-MIB::termByIP.0 = 192.0.2.1
    snmpset -m +ACCEL-PPP-MIB -v 2c -c local 127.0.0.1 ACCEL-PPP-MIB::termByUsername.0 = user1

    # Run a CLI command.
    snmpset -m +ACCEL-PPP-MIB -v 2c -c local 127.0.0.1 ACCEL-PPP-MIB::cli.0 = "shaper change all 1024 temp"


Encrypted chap-secrets
======================

The chap-secrets module supports encrypted passwords through OpenSSL. Set
encrypted=1 in the [chap-secrets] section. Usernames may remain in cleartext or
be transformed through a hash chain configured with username-hash, for example:

    [chap-secrets]
    encrypted=1
    username-hash=md5,sha1

Hashed usernames must be hexadecimal digest values. Passwords must contain the
NT hash produced by smbencrypt. Encrypted secrets are incompatible with the
auth_chap_md5 module. Hash chains are applied from left to right; for
username-hash=md5,sha1, the binary MD5 result is passed to SHA-1 and the final
digest is stored as hexadecimal.


Kernel module warning
=====================

The out-of-tree PPTP module conflicts with the kernel's ip_gre module. Do not
build ip_gre into the kernel or load it at runtime when using that PPTP module.
Do not mix ACCEL-PPP PPTP connections with poptop's pptpd; stop existing pptpd
sessions before starting ACCEL-PPP.


More information
================

* Project website: https://accel-ppp.org/
* Source and issue tracker: https://github.com/accel-ppp/accel-ppp
* Additional RADIUS notes: docs/
* Email: contact@accel-ppp.org
* ICQ: 337258064
* Jabber: dima@accel-ppp.org
