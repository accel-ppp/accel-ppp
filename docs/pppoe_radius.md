# Supplying PPPoE Session Parameters via RADIUS

accel-ppp supports configuring PPPoE sessions dynamically via RADIUS Access-Accept attributes. Unlike IPoE which maps attributes to DHCP options, PPPoE sessions are configured using standard PPP IPCP/IPv6CP negotiation and internal session parameters.

## Standard IPCP Configuration

These attributes control the IPv4 configuration negotiated with the client via IPCP.

*   **Framed-IP-Address** (8)
    *   Assigns the IPv4 address to the client.
    *   Value: IPv4 address (e.g., `192.168.0.100`) or `255.255.255.254` to instruct the NAS to select an address from a pool (if configured).

*   **MS-Primary-DNS-Server** (Vendor: Microsoft, ID: 28)
    *   Primary DNS server address to send to the client.
    
*   **MS-Secondary-DNS-Server** (Vendor: Microsoft, ID: 29)
    *   Secondary DNS server address.

*   **MS-Primary-NBNS-Server** (Vendor: Microsoft, ID: 30)
    *   Primary NetBIOS/WINS server address.

*   **MS-Secondary-NBNS-Server** (Vendor: Microsoft, ID: 31)
    *   Secondary NetBIOS/WINS server address.

## IPv6 Configuration

These attributes control the IPv6 configuration negotiated via IPv6CP and DHCPv6/SLAAC.

*   **Framed-Interface-Id** (96)
    *   Assigns the Interface Identifier (lower 64 bits) for the client's IPv6 address.

*   **Framed-IPv6-Prefix** (97)
    *   Assigns an IPv6 prefix to the client (typically via SLAAC).

*   **Delegated-IPv6-Prefix** (123)
    *   Prefix delegation (IA_PD) via DHCPv6.

*   **Framed-IPv6-Route** (99)
    *   Adds a route to the client session for the specified IPv6 prefix.
    *   Format: `2001:db8::/32 gateway metric`

*   **DNS-Server-IPv6-Address** (169, RFC 6911)
    *   Assigns an IPv6 DNS server to this session. Repeat the attribute for multiple servers.
    *   Assigned servers replace the `[ipv6-dns]` defaults for the session. Sessions without assigned servers use those defaults.
    *   Enable `ipv6_nd` to advertise the servers through RDNSS, `ipv6_dhcp` to return them through DHCPv6 DNS_SERVERS, or both as needed.
    *   The list is not limited to three servers; each reply includes as many as fit in its packet buffer and logs a warning if servers are omitted.

## Routing

*   **Framed-Route** (22)
    *   Adds a static route to the client session.
    *   Format: `192.168.10.0/24 192.168.0.100 1` (Network Gateway Metric)

## Session Management

*   **Session-Timeout** (27)
    *   Maximum duration of the session in seconds. The session is terminated after this time.

*   **Idle-Timeout** (28)
    *   Maximum idle time in seconds. The session is terminated if no traffic is detected for this duration.

*   **Acct-Interim-Interval** (85)
    *   Interval in seconds for sending Interim-Update accounting packets.

*   **Accel-VRF-Name** (Vendor: Accel-PPP, ID: 1)
    *   Assigns the session to a specific VRF (Virtual Routing and Forwarding) context.

## Rate Limiting (Shaper)

The `shaper` module can be configured to listen for specific RADIUS attributes to apply bandwidth limits. By default, it uses `Filter-Id`.

*   **Filter-Id** (11)
    *   Used to specify upload/download limits.
    *   **Simple Format:** `speed` or `downstream/upstream`, in Kbit/s with the default `rate-multiplier=1`.
        *   Example: `10000` sets both directions to 10 Mbps; `10000/2000` sets downstream to 10 Mbps and upstream to 2 Mbps.
        *   The slash separates rates. Configure bursts with `[shaper] down-burst-factor` and `up-burst-factor`.
    *   **Cisco Format:** Set `vendor=Cisco` and `attr=Cisco-AVPair` in `[shaper]`. Values such as `lcp:interface-config#1=rate-limit output 8000000 1500000 3000000 conform-action transmit exceed-action drop` control downstream; `rate-limit input ...` controls upstream. Cisco rates are in bits/sec and bursts are in bytes. See the [README shaper examples](../README.md#built-in-shaper) for time ranges and complete examples.
    
*   **Mikrotik-Rate-Limit** (Vendor: Mikrotik, ID: 8)
    *   Set `vendor=Mikrotik` and `attr=Mikrotik-Rate-Limit` in `[shaper]` to select this attribute. Its first rate is upstream and its second rate is downstream, the reverse of the simple Filter-Id order.
    
Note: The attribute ID and Vendor ID for the shaper are configurable in the `[shaper]` section of `accel-ppp.conf`.

## PPPoE Specific Attributes

PPPoE discovery tags (like Service-Name) are generally handled by the server configuration, but TR-101 (Broadband Forum) tags can be processed if `tr101` support is enabled.

*   **TR-101 Attributes** (Vendor: ADSL-Forum)
    *   With `[pppoe] tr101=1`, accel-ppp extracts Agent-Circuit-Id and Agent-Remote-Id from TR-101 Vendor-Specific tags in client PADR packets and includes them in RADIUS authentication and accounting requests. PADO is a server response, not the source of these client tags.
