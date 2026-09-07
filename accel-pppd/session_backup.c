#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>

#include "events.h"
#include "triton.h"
#include "log.h"
#include "ap_session.h"
#include "backup.h"
#include "ap_session_backup.h"
#include "ipdb.h"

#include "memdebug.h"

#ifdef USE_BACKUP

#define add_tag(id, data, size) if (!backup_add_tag(m, id, 0, data, size)) return -1;
#define add_tag_int(id, data, size) if (!backup_add_tag(m, id, 1, data, size)) return -1;

static int session_save(struct ap_session *ses, struct backup_mod *m)
{
	struct ipv6db_addr_t *a;
	struct ses_tag_ipv6 ipv6;

	add_tag(SES_TAG_USERNAME, ses->username, strlen(ses->username));
	add_tag(SES_TAG_SESSIONID, ses->sessionid, AP_SESSIONID_LEN);
	add_tag(SES_TAG_START_TIME, &ses->start_time, sizeof(time_t));
	add_tag(SES_TAG_IFNAME, ses->ifname, strlen(ses->ifname));
	add_tag_int(SES_TAG_IFINDEX, &ses->ifindex, 4);

	if (ses->ipv4) {
		add_tag(SES_TAG_IPV4_ADDR, &ses->ipv4->addr, 4);
		add_tag(SES_TAG_IPV4_PEER_ADDR, &ses->ipv4->peer_addr, 4);
	}

	if (ses->ipv6) {
		add_tag(SES_TAG_IPV6_INTFID, &ses->ipv6->intf_id, 8);
		add_tag(SES_TAG_IPV6_PEER_INTFID, &ses->ipv6->peer_intf_id, 8);
		list_for_each_entry(a, &ses->ipv6->addr_list, entry) {
			ipv6.addr = a->addr;
			ipv6.prefix_len = a->prefix_len;
			add_tag(SES_TAG_IPV6_ADDR, &ipv6, sizeof(ipv6));
		}
	}

	//add_tag_int(PPP_TAG_FD, &ses->fd, sizeof(ses->fd));
	//add_tag_int(PPP_TAG_CHAN_FD, &ses->chan_fd, sizeof(ses->chan_fd));
	//add_tag_int(PPP_TAG_UNIT_FD, &ses->unit_fd, sizeof(ses->unit_fd));
	//add_tag_int(PPP_TAG_UNIT, &ses->unit_idx, sizeof(ses->unit_idx));

	//triton_event_fire(EV_PPP_SESSION_SAVE, &ev);

	return 0;
}

static int session_restore(struct ap_session *ses, struct backup_mod *m)
{
	struct backup_tag *t;
	time_t start_time;
	uint32_t ifindex;

	list_for_each_entry(t, &m->tag_list, entry) {
		switch(t->id) {
			case SES_TAG_USERNAME:
				ses->username = _malloc(t->size + 1);
				if (!ses->username) {
					log_emerg("out of memory");
					return -1;
				}
				memcpy(ses->username, t->data, t->size);
				ses->username[t->size] = 0;
				break;
			case SES_TAG_SESSIONID:
				memcpy(ses->sessionid, t->data, AP_SESSIONID_LEN);
				break;
			case SES_TAG_IFNAME:
				memcpy(ses->ifname, t->data, t->size);
				ses->ifname[t->size] = 0;
				break;
			case SES_TAG_START_TIME:
				memcpy(&start_time, t->data, sizeof(start_time));
				ses->start_time = start_time;
				break;
			case SES_TAG_IFINDEX:
				if (ses->backup->internal) {
					memcpy(&ifindex, t->data, sizeof(ifindex));
					ses->ifindex = ifindex;
				}
				break;
			/*case PPP_TAG_FD:
				ses->fd = *(int *)t->data;
				break;
			case PPP_TAG_CHAN_FD:
				ses->chan_fd = *(int *)t->data;
				break;
			case PPP_TAG_UNIT_FD:
				ses->chan_fd = *(int *)t->data;
				break;
			case PPP_TAG_UNIT:
				ses->unit_idx = *(int *)t->data;
				break;
			case PPP_TAG_IPV4_ADDR:
				if (!ses->ipv4) {
					ses->ipv4 = _malloc(sizeof(*ses->ipv4));
					memset(ses->ipv4, 0, sizeof(*ses->ipv4));
					ses->ipv4->owner = &ipdb;
				}
				ses->ipv4->addr = *(in_addr_t *)t->data;
				break;
			case PPP_TAG_IPV4_PEER_ADDR:
				if (!ses->ipv4) {
					ses->ipv4 = _malloc(sizeof(*ses->ipv4));
					memset(ses->ipv4, 0, sizeof(*ses->ipv4));
					ses->ipv4->owner = &ipdb;
				}
				ses->ipv4->peer_addr = *(in_addr_t *)t->data;
				break;*/
		}
	}

	return 0;
	//return establish_ses(ses);
}

static struct backup_module mod = {
	.id = MODID_COMMON,
	.save = session_save,
	.restore = session_restore,
};

static void init(void)
{
	backup_register_module(&mod);
}

DEFINE_INIT(101, init);

#endif
