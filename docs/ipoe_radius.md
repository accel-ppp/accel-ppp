# Supplying DHCP Options via RADIUS for IPoE Sessions

The `ipoe` module can copy DHCP options from RADIUS Access-Accept attributes
into DHCP Offer and ACK packets. Load both `ipoe` and `radius` in `[modules]`.
No additional option mapping is needed for the DHCP vendor described below.

## Attribute encoding

* Vendor ID: **54**, named `DHCP` in the shipped dictionary.
* Vendor format: **2,1** (a two-byte attribute type and a one-byte length).
* Attribute IDs below 256 identify DHCP option codes, such as 6 for DNS
  servers and 43 for Vendor-Specific Information.
* The attribute value is the DHCP option payload. accel-ppp adds the DHCP
  option code and length itself.

Both the RADIUS server and accel-ppp must have matching dictionary definitions.
The shipped definitions are in
[`accel-pppd/radius/dict/dictionary.dhcp`](../accel-pppd/radius/dict/dictionary.dhcp),
which the default RADIUS dictionary includes. A vendor declaration without
`format=2,1` uses a different wire encoding and will not match this dictionary.

Use named attributes from the dictionary in RADIUS policies. Numeric attribute
names alone do not supply accel-ppp with a dictionary definition: unknown
attributes are skipped.

## Dictionary definitions

Reuse existing definitions where available. This fragment shows the vendor
format, scope, and types used by the examples; do not duplicate definitions
already loaded by the RADIUS server:

```text
VENDOR DHCP 54 format=2,1
BEGIN-VENDOR DHCP
ATTRIBUTE DHCP-Domain-Name-Server 6 ipaddr array
ATTRIBUTE DHCP-Domain-Name 15 string
ATTRIBUTE DHCP-Interface-MTU-Size 26 short
ATTRIBUTE DHCP-Vendor 43 octets
ATTRIBUTE DHCP-Classless-Static-Route 121 octets
END-VENDOR DHCP
```

For a private-use option such as 224, add a definition on **both** sides.
For example, insert this inside the DHCP vendor block in each local dictionary:

```text
ATTRIBUTE DHCP-Private-224 224 octets
```

## FreeRADIUS 3 example

Add reply attributes to the user's entry in the `files` module's users file.
For example, for a test account:

```text
test_user Cleartext-Password := "test_password"
	DHCP-Domain-Name-Server := 8.8.8.8,
	DHCP-Domain-Name-Server += 8.8.4.4,
	DHCP-Domain-Name := "example.com",
	DHCP-Interface-MTU-Size := 1450,
	DHCP-Vendor := 0x0103414243,
	DHCP-Classless-Static-Route := 0x080ac0a80101,
	DHCP-Private-224 := 0x48656c6c6f
```

The named `ipaddr`, `string`, and `short` attributes let FreeRADIUS encode
their payloads from readable values. The `octets` attributes use hexadecimal
payloads:

| DHCP option | Payload in this example |
| --- | --- |
| 6, DNS servers | `8.8.8.8` and `8.8.4.4`; repeated array values are combined into one DHCP option. |
| 15, domain name | The string `example.com`. |
| 26, interface MTU | `1450`, encoded as the two bytes `05aa`. |
| 43, vendor information | Sub-option 1, length 3, value `ABC`: `01 03 41 42 43`. |
| 121, classless route | `10.0.0.0/8` via `192.168.1.1`: width `08`, destination `0a`, router `c0a80101`. |
| 224, private use | The string `Hello`, encoded as `48 65 6c 6c 6f`; requires the custom definition above. |

See the [FreeRADIUS users-file reference](https://www.freeradius.org/radiusd/man/users.html)
for entry matching and reply-list syntax. Integrate these reply attributes with
the authentication policy used by your deployment.

## Notes

* Preserve `format=2,1` when defining the DHCP vendor on the RADIUS server.
* Construct the internal payload of complex options, such as 43 and 121,
  before supplying the hexadecimal value. Do not include the outer DHCP
  option code and length.
* The DHCP vendor also defines IDs above 255 for packet header fields, such
  as `DHCP-Your-IP-Address`. These are handled separately and are not copied
  as DHCP options.
