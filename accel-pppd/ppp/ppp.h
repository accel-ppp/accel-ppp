#ifndef PPP_H
#define PPP_H

#include <sys/types.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>

#include "triton.h"
#include "list.h"
#include "ap_session.h"

/*
 * Packet header = Code, id, length.
 */
#define PPP_HEADERLEN	4
#define PPP_MTU 1500

/*
 * Protocol field values.
 */
#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_AT		0x29	/* AppleTalk Protocol */
#define PPP_IPX		0x2b	/* IPX protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define PPP_IPV6CP	0x8057	/* IPv6 Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_ECP		0x8053	/* Encryption Control Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029	/* Callback Control Protocol */
#define PPP_EAP		0xc227	/* Extensible Authentication Protocol */

struct ppp_t
{
	struct ap_session ses;

	struct triton_md_handler_t chan_hnd;
	struct triton_md_handler_t unit_hnd;
	int fd;
	int chan_fd;
	int unit_fd;

	int chan_idx;

	int mtu;
	int mru;

	void *buf;
	int buf_size;

	struct list_head chan_handlers;
	struct list_head unit_handlers;

	struct list_head layers;

	/** 
	 * In non-dev-ppp environment, channel and unit reads would be performed
	 * through the same socket and will use the same handler/function.
	 * This flag sets that additionally unit handlers would be used.
	 */
	int is_unit_read_enabled;
};

struct ppp_layer_t;
struct layer_node_t;
struct ppp_layer_data_t
{
	struct list_head entry;
	struct ppp_layer_t *layer;
	struct layer_node_t *node;
	unsigned int passive:1;
	unsigned int optional:1;
	unsigned int starting:1;
	unsigned int started:1;
	unsigned int finished:1;
};

struct ppp_layer_t
{
	struct list_head entry;
	struct ppp_layer_data_t *(*init)(struct ppp_t *);
	int (*start)(struct ppp_layer_data_t*);
	void (*finish)(struct ppp_layer_data_t*);
	void (*free)(struct ppp_layer_data_t *);
};

struct ppp_handler_t
{
	struct list_head entry;
	int proto;
	void (*recv)(struct ppp_handler_t*);
	void (*recv_proto_rej)(struct ppp_handler_t *h);
};

void ppp_init(struct ppp_t *ppp);
int establish_ppp(struct ppp_t *ppp);
int connect_ppp_channel(struct ppp_t *ppp);
int ppp_chan_send(struct ppp_t *ppp, void *data, int size);
int ppp_unit_send(struct ppp_t *ppp, void *data, int size);
void lcp_send_proto_rej(struct ppp_t *ppp, uint16_t proto);
void ppp_recv_proto_rej(struct ppp_t *ppp, uint16_t proto);

void ppp_layer_started(struct ppp_t *ppp,struct ppp_layer_data_t*);
void ppp_layer_finished(struct ppp_t *ppp,struct ppp_layer_data_t*);
void ppp_layer_passive(struct ppp_t *ppp,struct ppp_layer_data_t*);

int ppp_terminate(struct ap_session *ses, int hard);

void ppp_register_chan_handler(struct ppp_t *, struct ppp_handler_t *);
void ppp_register_unit_handler(struct ppp_t * ,struct ppp_handler_t *);
void ppp_unregister_handler(struct ppp_t *, struct ppp_handler_t *);

int ppp_register_layer(const char *name, struct ppp_layer_t *);
void ppp_unregister_layer(struct ppp_layer_t *);
struct ppp_layer_data_t *ppp_find_layer_data(struct ppp_t *, struct ppp_layer_t *);

extern int conf_ppp_verbose;

#endif
