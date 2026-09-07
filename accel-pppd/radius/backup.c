#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "log.h"
#include "memdebug.h"
#include "utils.h"

#include "backup.h"
#include "ap_session_backup.h"
#include "radius_p.h"

#define RAD_TAG_INTERIM_INTERVAL            1
#define RAD_TAG_SESSION_TIMEOUT             2
#define RAD_TAG_IPV4_ADDR                   3
#define RAD_TAG_IPV6_ADDR                   4
#define RAD_TAG_IPV6_DP                     5
#define RAD_TAG_ATTR_CLASS                  6
#define RAD_TAG_ATTR_STATE                  7
#define RAD_TAG_TERMINATION_ACTION          8
#define RAD_TAG_ACCT_SERVER_ADDR            9
#define RAD_TAG_ACCT_SERVER_PORT           10
#define RAD_TAG_IDLE_TIMEOUT               11

#define RAD_TAG_ACCT_USERNAME              12


#define add_tag(id, data, size) if (!backup_add_tag(m, id, 0, data, size)) return -1;
#define add_tag_int(id, data, size) if (!backup_add_tag(m, id, 1, data, size)) return -1;

static int session_save(struct ap_session *ses, struct backup_mod *m)
{
	struct radius_pd_t *rpd = find_pd(ses);
	uint64_t session_timeout;
	uint32_t idle_timeout;

	if (!rpd)
		return 0;

	if (!rpd->authenticated)
		return -2;

	session_timeout = ses->start_time + rpd->session_timeout.expire_tv.tv_sec;
	idle_timeout = rpd->idle_timeout.period / 1000;

	add_tag(RAD_TAG_INTERIM_INTERVAL, &rpd->acct_interim_interval, 4);
	add_tag(RAD_TAG_INTERIM_JITTER, &rpd->acct_interim_jitter, 4);

	if (rpd->session_timeout.tpd)
		add_tag(RAD_TAG_SESSION_TIMEOUT, &session_timeout, 8);

	if (rpd->idle_timeout.tpd)
		add_tag(RAD_TAG_IDLE_TIMEOUT, &idle_timeout, 4);

	if (ses->ipv4 == &rpd->ipv4_addr)
		add_tag(RAD_TAG_IPV4_ADDR, NULL, 0);

	if (ses->ipv6 == &rpd->ipv6_addr)
		add_tag(RAD_TAG_IPV6_ADDR, NULL, 0);

	/*if (rpd->ipv6_pd_assigned) {

	}*/

	if (rpd->attr_class)
		add_tag(RAD_TAG_ATTR_CLASS, rpd->attr_class, rpd->attr_class_len);

	if (rpd->attr_state)
		add_tag(RAD_TAG_ATTR_CLASS, rpd->attr_state, rpd->attr_state_len);

	add_tag(RAD_TAG_TERMINATION_ACTION, &rpd->termination_action, 4);

	if (rpd->acct_username)
		add_tag(RAD_TAG_ACCT_USERNAME, rpd->acct_username, strlen(rpd->acct_username));

	if (rpd->acct_req) {
		add_tag(RAD_TAG_ACCT_SERVER_ADDR, &rpd->acct_req->server_addr, 4);
		add_tag(RAD_TAG_ACCT_SERVER_PORT, &rpd->acct_req->server_port, 2);
	}

	return 0;
}

static int session_restore(struct ap_session *ses, struct backup_mod *m)
{
	return 0;
}

static void restore_ipv4_addr(struct ap_session *ses)
{
	struct backup_mod *m = backup_find_mod(ses->backup, MODID_COMMON);
	struct backup_tag *tag;

	list_for_each_entry(tag, &m->tag_list, entry) {
		switch (tag->id) {
			case SES_TAG_IPV4_ADDR:
				ses->ipv4->addr = u_read_native32(tag->data);
				break;
			case SES_TAG_IPV4_PEER_ADDR:
				ses->ipv4->peer_addr = u_read_native32(tag->data);
				break;
		}
	}
}

static void restore_ipv6_addr(struct ap_session *ses)
{

}

void radius_restore_session(struct ap_session *ses, struct radius_pd_t *rpd)
{
	struct backup_mod *m = backup_find_mod(ses->backup, MODID_RADIUS);
	struct backup_tag *tag;
	in_addr_t acct_addr = 0;
	int acct_port;

	if (!m)
		return;

	list_for_each_entry(tag, &m->tag_list, entry) {
		switch (tag->id) {
			case RAD_TAG_INTERIM_INTERVAL:
				rpd->acct_interim_interval = u_read_native32(tag->data);
				break;
			case RAD_TAG_INTERIM_JITTER:
				rpd->acct_interim_jitter = u_read_native32(tag->data);
				break;
			case RAD_TAG_SESSION_TIMEOUT:
				rpd->session_timeout.expire_tv.tv_sec = u_read_native64(tag->data) - ses->start_time;
				break;
			case RAD_TAG_IDLE_TIMEOUT:
				rpd->idle_timeout.period = u_read_native32(tag->data) * 1000;
				break;
			case RAD_TAG_IPV4_ADDR:
				ses->ipv4 = &rpd->ipv4_addr;
				restore_ipv4_addr(ses);
				break;
			case RAD_TAG_IPV6_ADDR:
				restore_ipv6_addr(ses);
				break;
			case RAD_TAG_ATTR_CLASS:
				rpd->attr_class = _malloc(tag->size);
				memcpy(rpd->attr_class, tag->data, tag->size);
				rpd->attr_class_len = tag->size;
				break;
			case RAD_TAG_ATTR_STATE:
				rpd->attr_state = _malloc(tag->size);
				memcpy(rpd->attr_state, tag->data, tag->size);
				rpd->attr_state_len = tag->size;
				break;
			case RAD_TAG_TERMINATION_ACTION:
				rpd->termination_action = u_read_native32(tag->data);
				break;
			case RAD_TAG_ACCT_USERNAME:
				rpd->acct_username = _strndup(tag->data, tag->size);
				break;
			case RAD_TAG_ACCT_SERVER_ADDR:
				acct_addr = u_read_native32(tag->data);
				break;
			case RAD_TAG_ACCT_SERVER_PORT:
				acct_port = u_read_native16(tag->data);
				break;
		}
	}

	if (acct_addr)
		rpd->acct_req = rad_req_alloc2(rpd, CODE_ACCOUNTING_REQUEST, rpd->ses->username, acct_addr, acct_port);

	rpd->authenticated = 1;
}

static struct backup_module mod = {
	.id = MODID_RADIUS,
	.save = session_save,
	.restore = session_restore,
};

static void init(void)
{
	backup_register_module(&mod);
}

DEFINE_INIT(100, init);
