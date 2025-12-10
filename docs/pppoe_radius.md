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
    *   **Simple Format:** `speed` (bits/sec) or `speed/burst`. 
        *   Example: `10000` (10 Mbps)
    *   **Cisco Format:** `rate-limit output access-group 1 8000000 1500000 3000000` (downstream) / `rate-limit input ...` (upstream).
    
*   **Mikrotik-Rate-Limit** (Vendor: Mikrotik, ID: 8)
    *   Supported if the attribute is present.
    
Note: The attribute ID and Vendor ID for the shaper are configurable in the `[shaper]` section of `accel-ppp.conf`.

## PPPoE Specific Attributes

PPPoE discovery tags (like Service-Name) are generally handled by the server configuration, but TR-101 (Broadband Forum) tags can be processed if `tr101` support is enabled.

*   **TR-101 Attributes** (Vendor: ADSL-Forum)
    *   accel-ppp can parse Agent-Circuit-Id and Agent-Remote-Id from PADO/PADR packets if they are present in Vendor-Specific tags, and these can be used for authentication or accounting logging.
