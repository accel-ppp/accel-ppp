#ifndef PPP_IPCP_H
#define PPP_IPCP_H

#include <stdint.h>

#include "triton.h"
#include "ppp_fsm.h"
/*
 * Options.
 */
#define CI_COMP	2	  /* IP-Compress-Protocol */
#define CI_ADDR 3   /* IP-Address */
#define CI_DNS1 129 /* Primary-DNS-Address */
#define CI_DNS2 131 /* Secondary-DNS-Address */
#define CI_WINS1 130 /* Primary-NBNS-Address */
#define CI_WINS2 132 /* Secondary-NBNS-Address */

struct ipcp_hdr_t
{
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));
struct ipcp_opt_hdr_t
{
	uint8_t id;
	uint8_t len;
} __attribute__((packed));
struct ipcp_opt8_t
{
	struct ipcp_opt_hdr_t hdr;
	uint8_t val;
} __attribute__((packed));
struct ipcp_opt16_t
{
	struct ipcp_opt_hdr_t hdr;
	uint16_t val;
} __attribute__((packed));
struct ipcp_opt32_t
{
	struct ipcp_opt_hdr_t hdr;
	uint32_t val;
} __attribute__((packed));

#define IPCP_OPT_NONE  0
#define IPCP_OPT_ACK   1
#define IPCP_OPT_NAK  -1
#define IPCP_OPT_REJ  -2
#define IPCP_OPT_CLOSE -3
#define IPCP_OPT_TERMACK -4
#define IPCP_OPT_FAIL -5

struct ppp_ipcp_t;
struct ipcp_option_handler_t;

struct ipcp_option_t
{
	struct list_head entry;
	int id;
	int len;
	int state;
	unsigned int print:1;
	struct ipcp_option_handler_t *h;
};

struct ipcp_option_handler_t
{
	struct list_head entry;
	struct ipcp_option_t* (*init)(struct ppp_ipcp_t*);
	int (*send_conf_req)(struct ppp_ipcp_t*,struct ipcp_option_t*,uint8_t*);
	int (*send_conf_rej)(struct ppp_ipcp_t*,struct ipcp_option_t*,uint8_t*);
	int (*send_conf_nak)(struct ppp_ipcp_t*,struct ipcp_option_t*,uint8_t*);
	int (*recv_conf_req)(struct ppp_ipcp_t*,struct ipcp_option_t*,uint8_t*);
	int (*recv_conf_rej)(struct ppp_ipcp_t*,struct ipcp_option_t*,uint8_t*);
	int (*recv_conf_nak)(struct ppp_ipcp_t*,struct ipcp_option_t*,uint8_t*);
	int (*recv_conf_ack)(struct ppp_ipcp_t*,struct ipcp_option_t*,uint8_t*);
	void (*free)(struct ppp_ipcp_t*,struct ipcp_option_t*);
	void (*print)(void (*print)(const char *fmt,...), struct ipcp_option_t*,uint8_t*);
};

struct ppp_ipcp_t
{
	struct ppp_layer_data_t ld;
	struct ppp_handler_t hnd;
	struct ppp_fsm_t fsm;
	struct ppp_t *ppp;
	struct list_head options;

	struct triton_timer_t timeout;

	struct list_head ropt_list; // last received ConfReq
	int ropt_len;

	int conf_req_len;
	unsigned int starting:1;
	unsigned int started:1;
	unsigned int delay_ack:1;
};

int ipcp_option_register(struct ipcp_option_handler_t *h);
struct ipcp_option_t *ipcp_find_option(struct ppp_t *ppp, struct ipcp_option_handler_t *h);

#endif

