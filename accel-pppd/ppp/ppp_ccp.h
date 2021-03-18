#ifndef PPP_CCP_H
#define PPP_CCP_H

#include <stdint.h>

#include "triton.h"
#include "ppp_fsm.h"
/*
 * Options.
 */

#define CI_MPPE	18	  /* MPPE */

struct ccp_hdr_t
{
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));
struct ccp_opt_hdr_t
{
	uint8_t id;
	uint8_t len;
} __attribute__((packed));
struct ccp_opt8_t
{
	struct ccp_opt_hdr_t hdr;
	uint8_t val;
} __attribute__((packed));
struct ccp_opt16_t
{
	struct ccp_opt_hdr_t hdr;
	uint16_t val;
} __attribute__((packed));
struct ccp_opt32_t
{
	struct ccp_opt_hdr_t hdr;
	uint32_t val;
} __attribute__((packed));

#define CCP_OPT_NONE  0
#define CCP_OPT_ACK   1
#define CCP_OPT_NAK  -1
#define CCP_OPT_REJ  -2
#define CCP_OPT_FAIL -3

struct ppp_ccp_t;
struct ccp_option_handler_t;

struct ccp_option_t
{
	struct list_head entry;
	int id;
	int len;
	int state;
	struct ccp_option_handler_t *h;
};

struct ccp_option_handler_t
{
	struct list_head entry;
	struct ccp_option_t* (*init)(struct ppp_ccp_t*);
	int (*send_conf_req)(struct ppp_ccp_t*,struct ccp_option_t*,uint8_t*);
	int (*send_conf_rej)(struct ppp_ccp_t*,struct ccp_option_t*,uint8_t*);
	int (*send_conf_nak)(struct ppp_ccp_t*,struct ccp_option_t*,uint8_t*);
	int (*recv_conf_req)(struct ppp_ccp_t*,struct ccp_option_t*,uint8_t*);
	int (*recv_conf_rej)(struct ppp_ccp_t*,struct ccp_option_t*,uint8_t*);
	int (*recv_conf_nak)(struct ppp_ccp_t*,struct ccp_option_t*,uint8_t*);
	int (*recv_conf_ack)(struct ppp_ccp_t*,struct ccp_option_t*,uint8_t*);
	void (*free)(struct ppp_ccp_t*,struct ccp_option_t*);
	void (*print)(void (*print)(const char *fmt,...), struct ccp_option_t*,uint8_t*);
};

struct ppp_ccp_t
{
	struct ppp_layer_data_t ld;
	struct ppp_handler_t hnd;
	struct ppp_fsm_t fsm;
	struct ppp_t *ppp;
	struct list_head options;

	struct list_head ropt_list; // last received ConfReq
	int ropt_len;

	int conf_req_len;
	unsigned int starting:1;
	unsigned int started:1;
};

int ccp_option_register(struct ccp_option_handler_t *h);
struct ccp_option_t *ccp_find_option(struct ppp_t *ppp, struct ccp_option_handler_t *h);

struct ppp_ccp_t *ccp_find_layer_data(struct ppp_t *ppp);
int ccp_ipcp_started(struct ppp_t *ppp);

#endif

