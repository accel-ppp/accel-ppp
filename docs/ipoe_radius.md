# Supplying DHCP Options via RADIUS for IPoE Sessions

accel-ppp supports dynamically providing various DHCP options to IPoE clients by configuring corresponding RADIUS attributes. This allows for flexible and centralized management of DHCP parameters delivered to clients.

## Mechanism

The `ipoe` module processes RADIUS Access-Accept packets to extract DHCP options that need to be delivered to the client. This is achieved by mapping specific RADIUS Vendor-Specific Attributes (VSAs) to DHCP options. Whether you're sending a standard DHCP option (like DNS servers) or the DHCP-specific "Vendor-Specific Information" option (Option 43), the mechanism uses this common VSA structure:

*   **RADIUS Vendor ID:** `54`
    *   This ID is internally designated by accel-ppp (and commonly in FreeRADIUS dictionaries) as the "DHCP" vendor.
*   **RADIUS Attribute ID:** This directly corresponds to the **DHCP Option Code** you wish to send (e.g., `6` for DNS Servers, `43` for Vendor-Specific Information).
*   **RADIUS Attribute Value:** This is the raw binary payload (octets) of the DHCP option. accel-ppp will encapsulate this value into the DHCP option's data field.

When accel-ppp receives an Access-Accept packet containing attributes structured in this way, it extracts the DHCP Option Code and its value, then constructs the appropriate DHCP option and includes it in the DHCP Offer or DHCP ACK packet sent back to the IPoE client.

## Configuration

### accel-ppp Side

The functionality is inherent to the `ipoe` module; no special configuration options are required in `accel-ppp.conf` to enable this mapping. Ensure the `ipoe` module is loaded.

### RADIUS Server Side

To leverage this feature, your RADIUS server must be configured to send attributes using the Vendor ID `54` (DHCP) and the desired DHCP Option Code as the Attribute ID.

**FreeRADIUS Example:**

1. **Ensure Dictionary Definitions:**
    Your FreeRADIUS installation should have dictionary files that define Vendor 54 as "DHCP" and the relevant DHCP Option Codes as attributes within that vendor space. The `accel-ppp` project often provides a `dictionary.dhcp` file (e.g., in `accel-pppd/radius/dict/`) with these definitions:

    ```text
    VENDOR      DHCP        54
    ATTRIBUTE   DHCP-Vendor 43  octets
    # ... other DHCP option definitions
    ```

2. **Configure Reply Attributes in `users` file (or equivalent policy):**
    The format for specifying these attributes is generally `Attr-<Vendor-ID>-<Attribute-ID> = <value>`.

    *   **Generic DHCP Option (e.g., Option 224, private use, with string "Hello"):**
        ```text
        User-Name == "test_user"
            Attr-54-224 = "Hello"
        ```

    *   **Option 6 (DNS Servers):**
        To send a list of DNS server IP addresses (e.g., `8.8.8.8` and `8.8.4.4`). The value is the concatenation of the 4-byte IP addresses in hexadecimal.
        ```text
        User-Name == "test_user"
            Attr-54-6 = 0x0808080808080404
        ```

    *   **Option 15 (Domain Name):**
        To send a domain name string (e.g., `example.com`).
        ```text
        User-Name == "test_user"
            Attr-54-15 = "example.com"
        ```

    *   **Option 26 (Interface MTU):**
        To send a specific MTU size (e.g., `1450`). The value is a 16-bit integer (2 bytes) in hexadecimal.
        ```text
        User-Name == "test_user"
            Attr-54-26 = 0x05AA # 1450 in hex is 0x05AA
        ```

    *   **Option 43 (Vendor-Specific Information):**
        This option typically contains sub-options encoded in a TLV (Type-Length-Value) format. The entire TLV structure for Option 43 needs to be provided as the attribute's hexadecimal value.

        *Example: Sending sub-option `1` with value `"ABC"`*
        *   Sub-option Type: `1` (0x01)
        *   Sub-option Length: `3` (0x03)
        *   Sub-option Value: `"ABC"` (0x414243)
        *   Combined Hex Value: `0103414243`

        ```text
        User-Name == "test_user"
            Attr-54-43 = 0x0103414243
        ```

    *   **Option 121 (Classless Static Route):**
        To send static routes. The format for the value is a sequence of `(Mask Width, Significant Octets of Destination, Router IP)`.

        *Example: Route `10.0.0.0/8` via `192.168.1.1`*
        *   Mask Width: `8` (0x08)
        *   Significant Octets of Destination: `10` (0x0a) - only 1 byte for a /8 network
        *   Router IP: `192.168.1.1` (0xc0a80101)
        *   Combined Hex Value: `080ac0a80101`

        ```text
        User-Name == "test_user"
            Attr-54-121 = 0x080ac0a80101
        ```

## Notes

*   The RADIUS attribute value must strictly be the raw payload of the DHCP option. accel-ppp automatically handles inserting the DHCP Option Code and Length fields into the final DHCP packet.
*   For complex DHCP options like Option 43 (Vendor-Specific Information) and Option 121 (Classless Static Route), you must manually construct the internal structure (e.g., TLVs for Option 43) as part of the RADIUS attribute value.
