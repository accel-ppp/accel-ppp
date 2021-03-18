#ifndef PPP_IPV6CP_H
#define PPP_IPV6CP_H

#include <stdint.h>

#include "triton.h"
#include "ppp_fsm.h"
/*
 * Options.
 */
#define CI_INTFID	1

struct ipv6cp_hdr_t
{
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

struct ipv6cp_opt_hdr_t
{
	uint8_t id;
	uint8_t len;
} __attribute__((packed));

struct ipv6cp_opt8_t
{
	struct ipv6cp_opt_hdr_t hdr;
	uint8_t val;
} __attribute__((packed));

struct ipv6cp_opt16_t
{
	struct ipv6cp_opt_hdr_t hdr;
	uint16_t val;
} __attribute__((packed));

struct ipv6cp_opt32_t
{
	struct ipv6cp_opt_hdr_t hdr;
	uint32_t val;
} __attribute__((packed));

struct ipv6cp_opt64_t
{
	struct ipv6cp_opt_hdr_t hdr;
	uint64_t val;
} __attribute__((packed));


#define IPV6CP_OPT_NONE  0
#define IPV6CP_OPT_ACK   1
#define IPV6CP_OPT_NAK  -1
#define IPV6CP_OPT_REJ  -2
#define IPV6CP_OPT_CLOSE -3
#define IPV6CP_OPT_TERMACK -4
#define IPV6CP_OPT_FAIL -5

struct ppp_ipv6cp_t;
struct ipv6cp_option_handler_t;

struct ipv6cp_option_t
{
	struct list_head entry;
	int id;
	int len;
	int state;
	unsigned int print:1;
	struct ipv6cp_option_handler_t *h;
};

struct ipv6cp_option_handler_t
{
	struct list_head entry;
	struct ipv6cp_option_t* (*init)(struct ppp_ipv6cp_t*);
	int (*send_conf_req)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*,uint8_t*);
	int (*send_conf_rej)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*,uint8_t*);
	int (*send_conf_nak)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*,uint8_t*);
	int (*recv_conf_req)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*,uint8_t*);
	int (*recv_conf_rej)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*,uint8_t*);
	int (*recv_conf_nak)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*,uint8_t*);
	int (*recv_conf_ack)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*,uint8_t*);
	void (*free)(struct ppp_ipv6cp_t*,struct ipv6cp_option_t*);
	void (*print)(void (*print)(const char *fmt,...), struct ipv6cp_option_t*,uint8_t*);
};

struct ppp_ipv6cp_t
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

int ipv6cp_option_register(struct ipv6cp_option_handler_t *h);

#endif

