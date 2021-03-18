#ifndef PPP_LCP_H
#define PPP_LCP_H

#include <stdint.h>

#include "triton.h"
#include "ppp.h"
#include "ppp_fsm.h"

/*
 * Options.
 */
#define CI_VENDOR	0	/* Vendor Specific */
#define CI_MRU		1	/* Maximum Receive Unit */
#define CI_ASYNCMAP	2	/* Async Control Character Map */
#define CI_AUTH    3	/* Authentication Type */
#define CI_QUALITY	4	/* Quality Protocol */
#define CI_MAGIC	5	/* Magic Number */
#define CI_PCOMP	7	/* Protocol Field Compression */
#define CI_ACCOMP 8	/* Address/Control Field Compression */
#define CI_FCSALTERN	9	/* FCS-Alternatives */
#define CI_SDP		10	/* Self-Describing-Pad */
#define CI_NUMBERED	11	/* Numbered-Mode */
#define CI_CALLBACK	13	/* callback */
#define CI_MRRU		17	/* max reconstructed receive unit; multilink */
#define CI_SSNHF	18	/* short sequence numbers for multilink */
#define CI_EPDISC	19	/* endpoint discriminator */
#define CI_MPPLUS	22	/* Multi-Link-Plus-Procedure */
#define CI_LDISC	23	/* Link-Discriminator */
#define CI_LCPAUTH	24	/* LCP Authentication */
#define CI_COBS		25	/* Consistent Overhead Byte Stuffing */
#define CI_PREFELIS	26	/* Prefix Elision */
#define CI_MPHDRFMT	27	/* MP Header Format */
#define CI_I18N		28	/* Internationalization */
#define CI_SDL		29	/* Simple Data Link */

struct lcp_hdr_t
{
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));
struct lcp_opt_hdr_t
{
	uint8_t id;
	uint8_t len;
} __attribute__((packed));
struct lcp_opt8_t
{
	struct lcp_opt_hdr_t hdr;
	uint8_t val;
} __attribute__((packed));
struct lcp_opt16_t
{
	struct lcp_opt_hdr_t hdr;
	uint16_t val;
} __attribute__((packed));
struct lcp_opt32_t
{
	struct lcp_opt_hdr_t hdr;
	uint32_t val;
} __attribute__((packed));

/*struct lcp_options_t
{
	int magic;
	int mtu;
	int mru;
	int accomp; // 0 - disabled, 1 - enable, 2 - allow, disabled, 3 - allow,enabled
	int pcomp;  // 0 - disabled, 1 - enable, 2 - allow, disabled, 3 - allow,enabled
	// negotiated options;
	int neg_mru;
	int neg_mtu;
	int neg_accomp; // -1 - rejected
	int neg_pcomp;
	int neg_auth[AUTH_MAX];
};*/

#define LCP_OPT_NONE  0
#define LCP_OPT_ACK   1
#define LCP_OPT_NAK  -1
#define LCP_OPT_REJ  -2
#define LCP_OPT_FAIL -3

struct ppp_lcp_t;
struct lcp_option_handler_t;

struct lcp_option_t
{
	struct list_head entry;
	int id;
	int len;
	int state;
	unsigned int print:1;
	struct lcp_option_handler_t *h;
};

struct lcp_option_handler_t
{
	struct list_head entry;
	struct lcp_option_t* (*init)(struct ppp_lcp_t*);
	int (*send_conf_req)(struct ppp_lcp_t*,struct lcp_option_t*,uint8_t*);
	int (*send_conf_rej)(struct ppp_lcp_t*,struct lcp_option_t*,uint8_t*);
	int (*send_conf_nak)(struct ppp_lcp_t*,struct lcp_option_t*,uint8_t*);
	int (*recv_conf_req)(struct ppp_lcp_t*,struct lcp_option_t*,uint8_t*);
	int (*recv_conf_rej)(struct ppp_lcp_t*,struct lcp_option_t*,uint8_t*);
	int (*recv_conf_nak)(struct ppp_lcp_t*,struct lcp_option_t*,uint8_t*);
	int (*recv_conf_ack)(struct ppp_lcp_t*,struct lcp_option_t*,uint8_t*);
	void (*free)(struct ppp_lcp_t*,struct lcp_option_t*);
	void (*print)(void (*print)(const char *fmt,...), struct lcp_option_t*,uint8_t*);
};

struct ppp_lcp_t
{
	struct ppp_layer_data_t ld;
	struct ppp_handler_t hnd;
	struct ppp_fsm_t fsm;
	struct ppp_t *ppp;
	struct list_head options;

	struct triton_timer_t echo_timer;
	int echo_sent;
	int magic;
	unsigned long last_ipackets;
	time_t last_echo_ts;

	struct list_head ropt_list; // last received ConfReq
	int ropt_len;

	int conf_req_len;
	unsigned int started:1;
};

int lcp_option_register(struct lcp_option_handler_t *h);

#endif

