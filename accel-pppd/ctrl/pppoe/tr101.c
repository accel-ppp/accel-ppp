#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "triton.h"
#include "ppp.h"
#include "log.h"
#include "radius.h"
#include "memdebug.h"
#include "utils.h"

#include "pppoe.h"

#define OPT_CIRCUIT_ID                0x01
#define OPT_REMOTE_AGENT_ID           0x02
#define OPT_ACTUAL_DATA_RATE_UP       0x81
#define OPT_ACTUAL_DATA_RATE_DOWN     0x82
#define OPT_MIN_DATA_RATE_UP          0x83
#define OPT_MIN_DATA_RATE_DOWN        0x84
#define OPT_ATT_DATA_RATE_UP          0x85
#define OPT_ATT_DATA_RATE_DOWN        0x86
#define OPT_MAX_DATA_RATE_UP          0x87
#define OPT_MAX_DATA_RATE_DOWN        0x88
#define OPT_MIN_DATA_RATE_UP_LP       0x89
#define OPT_MIN_DATA_RATE_DOWN_LP     0x8A
#define OPT_MAX_INTERL_DELAY_UP       0x8B
#define OPT_ACTUAL_INTERL_DELAY_UP    0x8C
#define OPT_MAX_INTER_DELAY_DOWN      0x8D
#define OPT_ACTUAL_INTER_DELAY_DOWN   0x8E
#define ACCESS_LOOP_ENCAP             0x90
#define IFW_SESSION                   0xFE

static int tr101_send_request(struct pppoe_tag *tr101, struct rad_packet_t *pack, int type)
{
	uint8_t *ptr = (uint8_t *)tr101->tag_data + 4;
	uint8_t *endptr = (uint8_t *)tr101->tag_data + ntohs(tr101->tag_len);
	int id, len;
	char str[64];

	while (ptr < endptr) {
		if (ptr + 2 > endptr)
			goto inval;
		id = *ptr++;
		len = *ptr++;
		if (ptr + len > endptr)
			goto inval;

		/* Section 4 of RFC 4679 states that attributes 0x83 to 0x8E
		 * mustn't be included in RADIUS access requests.
		 * This is in contradiction with the TR-101 specification
		 * which excludes attributes 0x85 to 0x90.
		 * Here, we follow the TR-101 guidelines.
		 */
		if (type && id >= 0x85 && id <= 0x90) {
			ptr += len;
			continue;
		}
		switch (id) {
			case OPT_CIRCUIT_ID:
				if (len > 63)
					goto inval;
				memcpy(str, ptr, len);
				str[len] = 0;
				if (rad_packet_add_str(pack, "ADSL-Forum", "ADSL-Agent-Circuit-Id", str))
					return -1;
				break;
			case OPT_REMOTE_AGENT_ID:
				if (len > 63)
					goto inval;
				memcpy(str, ptr, len);
				str[len] = 0;
				if (rad_packet_add_str(pack, "ADSL-Forum", "ADSL-Agent-Remote-Id", str))
					return -1;
				break;
			case OPT_ACTUAL_DATA_RATE_UP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Actual-Data-Rate-Upstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_ACTUAL_DATA_RATE_DOWN:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Actual-Data-Rate-Downstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MIN_DATA_RATE_UP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Minimum-Data-Rate-Upstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MIN_DATA_RATE_DOWN:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Minimum-Data-Rate-Downstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_ATT_DATA_RATE_UP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Attainable-Data-Rate-Upstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_ATT_DATA_RATE_DOWN:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Attainable-Data-Rate-Downstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MAX_DATA_RATE_UP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Maximum-Data-Rate-Upstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MAX_DATA_RATE_DOWN:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Maximum-Data-Rate-Downstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MIN_DATA_RATE_UP_LP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Minimum-Data-Rate-Upstream-Low-Power", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MIN_DATA_RATE_DOWN_LP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Minimum-Data-Rate-Downstream-Low-Power", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MAX_INTERL_DELAY_UP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Maximum-Interleaving-Delay-Upstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_ACTUAL_INTERL_DELAY_UP:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Actual-Interleaving-Delay-Upstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_MAX_INTER_DELAY_DOWN:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Maximum-Interleaving-Delay-Downstream", u_read_be32(ptr)))
					return -1;
				break;
			case OPT_ACTUAL_INTER_DELAY_DOWN:
				if (len != 4)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Actual-Interleaving-Delay-Downstream", u_read_be32(ptr)))
					return -1;
				break;
			case ACCESS_LOOP_ENCAP:
				if (len != 3)
					goto inval;
				/* Each byte in this tag represents an
				 * independent field: Data Link, Encaps 1
				 * and Encaps 2.
				 * TR-101 and RFC 4679 aggree on the meaning
				 * of the Encaps 1 and Encaps 2 fields. For
				 * Data Link, TR-101 states that 0 means AAL5
				 * and 1 means Ethernet, while RFC 4679 says
				 * AAL5 is 1 and Ethernet is 2.
				 *
				 * Currently, we build the RADIUS request using
				 * the tag received from PPPoE (TR-101 format).
				 * RFC 4679 format would require conversion.
				 */
				memcpy(str, ptr, 3);
				if (rad_packet_add_octets(pack, "ADSL-Forum", "Access-Loop-Encapsulation", (uint8_t *)str, 3))
					return -1;
				break;
			case IFW_SESSION:
				if (len != 0)
					goto inval;
				if (rad_packet_add_octets(pack, "ADSL-Forum", "IWF-Session", NULL, 0))
					return -1;
				break;
		}
		ptr += len;
	}

	return 0;

inval:
	log_ppp_warn("pppoe:tr101: invalid tag received\n");
	return -1;
}

int tr101_send_access_request(struct pppoe_tag *tr101, struct rad_packet_t *pack)
{
	return tr101_send_request(tr101, pack, 1);
}

int tr101_send_accounting_request(struct pppoe_tag *tr101, struct rad_packet_t *pack)
{
	return tr101_send_request(tr101, pack, 0);
}
