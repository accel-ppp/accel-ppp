/* Shared header for the l2tp-switch peer simulator; see l2tp_switch_peer_test.c. */
#ifndef L2TP_SWITCH_PEER_TEST_H
#define L2TP_SWITCH_PEER_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_pppox.h>
#include <time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "l2tp.h"
#include "l2tp_prot.h"
#include "attr_defs.h"
#include <openssl/md5.h>

extern struct sockaddr_in peer_addr;
extern const char *secret;
extern const char *calling_number;
extern const char *called_number;
extern const char *proxy_username;
extern const char *proxy_password;
extern const char *data_pattern;
extern int send_stopccn;
extern int wait_cdn;
extern int real_ppp;
extern int minimal_lcp;
enum { LCP_AUTH_NONE, LCP_AUTH_PAP, LCP_AUTH_CHAP };
extern int lcp_auth;
extern int hold_seconds;
extern int listen_mode;
extern int listen_rounds;
extern int sccrp_delay_ms;
extern int sccrp_storm_ms;
extern int cdn_timeout;
extern int cdn_after_lcp_ms;
extern int cdn_after_iccn_ms;
extern const char *second_call_number;
enum { FIN_FLOOD_OFF, FIN_FLOOD_ON_SCCRQ, FIN_FLOOD_ON_CDN, FIN_FLOOD_ON_ICCN };
extern int fin_flood_on;
extern int fin_flood_stopccn_ms;
extern int fin_flood_start_ms;
extern int fin_flood_len_ms;
extern uint16_t local_tid;
extern uint16_t local_sid;

int u_randbuf(void *buf, size_t buf_len, int *err);
int die(const char *msg);
double now_monotonic(void);

/* l2tp_switch_peer_lcp.c */
void comp_chap_md5(uint8_t *md5, uint8_t ident,
		   const void *secret, size_t secret_len,
		   const void *chall, size_t chall_len);
int run_real_ppp(int data_fd);
int run_minimal_lcp(int data_fd, int timeout_seconds);

/* l2tp_switch_peer_flood.c */
int parse_fin_flood(const char *spec);
int run_fin_flood(int fd, const struct sockaddr_in *their_addr,
		  uint16_t their_tid, uint16_t our_tid,
		  uint16_t ns, uint16_t nr);
extern int busy_flood_ms;
int run_busy_flood(int fd, const struct sockaddr_in *their_addr, int ms);

/* l2tp_switch_peer_listen.c */
int run_listen_mode(int rounds);

#endif /* L2TP_SWITCH_PEER_TEST_H */
