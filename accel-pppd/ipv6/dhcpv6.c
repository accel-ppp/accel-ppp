#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <endian.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>

#include "triton.h"
#include "mempool.h"
#include "log.h"
#include "ppp.h"
#include "ipdb.h"
#include "events.h"
#include "iputils.h"

#include "dhcpv6.h"

#include "memdebug.h"

#define BUF_SIZE 65536
#define MAX_DNS_COUNT 3

static struct {
	struct dhcpv6_opt_serverid hdr;
	uint64_t u64;
} __packed serverid;

int conf_verbose;
static int conf_pref_lifetime = 604800;
static int conf_valid_lifetime = 2592000;
static struct dhcpv6_opt_serverid *conf_serverid = &serverid.hdr;
static int conf_route_via_gw = 1;

static struct in6_addr conf_dns[MAX_DNS_COUNT];
static int conf_dns_count;
static uint8_t *conf_dnssl;
static int conf_dnssl_size;

struct dhcpv6_pd {
	struct ap_private pd;
	struct ap_session *ses;
	struct triton_md_handler_t hnd;
	struct dhcpv6_opt_clientid *clientid;
	uint32_t addr_iaid;
	uint32_t dp_iaid;
	unsigned int dp_active:1;
};

static void *pd_key;

static int dhcpv6_read(struct triton_md_handler_t *h);

static void ev_ses_started(struct ap_session *ses)
{
	struct ipv6_mreq mreq;
	struct dhcpv6_pd *pd;
	struct sockaddr_in6 addr;
	struct ipv6db_addr_t *a;
	int sock;
	int f = 1;

	if (!ses->ipv6 || list_empty(&ses->ipv6->addr_list))
		return;

	a = list_entry(ses->ipv6->addr_list.next, typeof(*a), entry);
	if (a->prefix_len == 0 || IN6_IS_ADDR_UNSPECIFIED(&a->addr))
		return;

	sock = net->socket(AF_INET6, SOCK_DGRAM, 0);
	if (!sock) {
		log_ppp_error("dhcpv6: socket: %s\n", strerror(errno));
		return;
	}

	net->setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &f, sizeof(f));

	if (net->setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ses->ifname, strlen(ses->ifname))) {
		log_ppp_error("ipv6_nd: setsockopt(SO_BINDTODEVICE): %s\n", strerror(errno));
		close(sock);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(DHCPV6_SERV_PORT);

	if (net->bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		log_ppp_error("dhcpv6: bind: %s\n", strerror(errno));
		close(sock);
		return;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_interface = ses->ifindex;
	mreq.ipv6mr_multiaddr.s6_addr32[0] = htonl(0xff020000);
	mreq.ipv6mr_multiaddr.s6_addr32[3] = htonl(0x010002);

	if (net->setsockopt(sock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		log_ppp_error("dhcpv6: failed to join to All_DHCP_Relay_Agents_and_Servers\n");
		close(sock);
		return;
	}

	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);
	net->set_nonblocking(sock, 1);

	pd = _malloc(sizeof(*pd));
	memset(pd, 0, sizeof(*pd));

	pd->pd.key = &pd_key;
	list_add_tail(&pd->pd.entry, &ses->pd_list);

	pd->ses = ses;

	pd->hnd.fd = sock;
	pd->hnd.read = dhcpv6_read;
	triton_md_register_handler(ses->ctrl->ctx, &pd->hnd);
	triton_md_enable_handler(&pd->hnd, MD_MODE_READ);
}

static struct dhcpv6_pd *find_pd(struct ap_session *ses)
{
	struct ap_private *pd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key)
			return container_of(pd, struct dhcpv6_pd, pd);
	}

	return NULL;
}

static void ev_ses_finished(struct ap_session *ses)
{
	struct dhcpv6_pd *pd = find_pd(ses);

	if (!pd)
		return;

	list_del(&pd->pd.entry);

	if (pd->clientid)
		_free(pd->clientid);

	if (ses->ipv6_dp) {
		if (pd->dp_active) {
			struct ipv6db_addr_t *p;
			list_for_each_entry(p, &ses->ipv6_dp->prefix_list, entry)
				ip6route_del(0, &p->addr, p->prefix_len, NULL, 0, 0);
		}

		ipdb_put_ipv6_prefix(ses, ses->ipv6_dp);
	}

	triton_md_unregister_handler(&pd->hnd, 1);

	_free(pd);
}

static void insert_dp_routes(struct ap_session *ses, struct dhcpv6_pd *pd, struct in6_addr *addr)
{
	struct ipv6db_addr_t *p;
	char str1[INET6_ADDRSTRLEN];
	char str2[INET6_ADDRSTRLEN];
	int err;

	if (!conf_route_via_gw || (addr && IN6_IS_ADDR_UNSPECIFIED(addr)))
		addr = NULL;

	list_for_each_entry(p, &ses->ipv6_dp->prefix_list, entry) {
		if (ip6route_add(ses->ifindex, &p->addr, p->prefix_len, addr, 0, 0)) {
			err = errno;
			inet_ntop(AF_INET6, &p->addr, str1, sizeof(str1));
			if (addr)
				inet_ntop(AF_INET6, addr, str2, sizeof(str2));
			log_ppp_error("dhcpv6: route add %s/%i%s%s: %s\n", str1, p->prefix_len,
					addr ? " via " : "", str2, strerror(err));
		} else if (conf_verbose) {
			inet_ntop(AF_INET6, &p->addr, str1, sizeof(str1));
			if (addr)
				inet_ntop(AF_INET6, addr, str2, sizeof(str2));
			log_ppp_info2("dhcpv6: route add %s/%i%s%s\n", str1, p->prefix_len,
					addr ? " via " : "", str2);
		}
	}

	pd->dp_active = 1;
}

static void insert_status(struct dhcpv6_packet *pkt, struct dhcpv6_option *opt, int code)
{
	struct dhcpv6_option *opt1;
	struct dhcpv6_opt_status *status;

	if (opt)
		opt1 = dhcpv6_nested_option_alloc(pkt, opt, D6_OPTION_STATUS_CODE, sizeof(struct dhcpv6_opt_status) - sizeof(struct dhcpv6_opt_hdr));
	else
		opt1 = dhcpv6_option_alloc(pkt, D6_OPTION_STATUS_CODE, sizeof(struct dhcpv6_opt_status) - sizeof(struct dhcpv6_opt_hdr));

	status = (struct dhcpv6_opt_status *)opt1->hdr;
	status->code = htons(code);
}

static void insert_oro(struct dhcpv6_packet *reply, struct dhcpv6_option *opt)
{
	struct dhcpv6_option *opt1;
	int i, j;
	uint16_t *ptr;
	struct in6_addr addr, *addr_ptr;

	for (i = ntohs(opt->hdr->len) / 2, ptr = (uint16_t *)opt->hdr->data; i; i--, ptr++) {
		if (ntohs(*ptr) == D6_OPTION_DNS_SERVERS) {
			if (conf_dns_count) {
				opt1 = dhcpv6_option_alloc(reply, D6_OPTION_DNS_SERVERS, conf_dns_count * sizeof(addr));
				for (j = 0, addr_ptr = (struct in6_addr *)opt1->hdr->data; j < conf_dns_count; j++, addr_ptr++)
					memcpy(addr_ptr, conf_dns + j, sizeof(addr));
			}
		} else if (ntohs(*ptr) == D6_OPTION_DOMAIN_LIST) {
			if (conf_dnssl_size) {
				opt1 = dhcpv6_option_alloc(reply, D6_OPTION_DOMAIN_LIST, conf_dnssl_size);
				memcpy(opt1->hdr->data, conf_dnssl, conf_dnssl_size);
			}
		}
	}
}

static void dhcpv6_send_reply(struct dhcpv6_packet *req, struct dhcpv6_pd *pd, int code)
{
	struct dhcpv6_packet *reply;
	struct dhcpv6_option *opt, *opt1, *opt2, *opt3;
	struct dhcpv6_opt_ia_na *ia_na;
	struct dhcpv6_opt_ia_addr *ia_addr;
	struct dhcpv6_opt_ia_prefix *ia_prefix;
	struct ipv6db_addr_t *a;
	struct in6_addr addr;
	struct ap_session *ses = req->ses;
	int f = 0, f1, f2 = 0;

	reply = dhcpv6_packet_alloc_reply(req, code);
	if (!reply)
		return;

	list_for_each_entry(opt, &req->opt_list, entry) {

		// IA_NA
		if (ntohs(opt->hdr->code) == D6_OPTION_IA_NA) {
			if (req->hdr->type == D6_INFORMATION_REQUEST)
				continue;

			opt1 = dhcpv6_option_alloc(reply, D6_OPTION_IA_NA, sizeof(struct dhcpv6_opt_ia_na) - sizeof(struct dhcpv6_opt_hdr));
			memcpy(opt1->hdr + 1, opt->hdr + 1, ntohs(opt1->hdr->len));

			ia_na = (struct dhcpv6_opt_ia_na *)opt1->hdr;
			ia_na->T1 = conf_pref_lifetime == -1 ? -1 : htonl(conf_pref_lifetime / 2);
			ia_na->T2 = conf_pref_lifetime == -1 ? -1 : htonl((conf_pref_lifetime * 4) / 5);

			if (req->hdr->type == D6_RENEW && pd->addr_iaid != ia_na->iaid) {
				insert_status(reply, opt1, D6_STATUS_NoBinding);
			} else if (list_empty(&ses->ipv6->addr_list) || f) {
				insert_status(reply, opt1, D6_STATUS_NoAddrsAvail);
			} else {

				if (req->hdr->type == D6_REQUEST || req->rapid_commit)
					pd->addr_iaid = ia_na->iaid;

				f = 1;

				list_for_each_entry(a, &ses->ipv6->addr_list, entry) {
					opt2 = dhcpv6_nested_option_alloc(reply, opt1, D6_OPTION_IAADDR, sizeof(*ia_addr) - sizeof(struct dhcpv6_opt_hdr));
					ia_addr = (struct dhcpv6_opt_ia_addr *)opt2->hdr;

					build_ip6_addr(a, ses->ipv6->peer_intf_id, &ia_addr->addr);

					ia_addr->pref_lifetime = htonl(conf_pref_lifetime);
					ia_addr->valid_lifetime = htonl(conf_valid_lifetime);

					if (!a->installed) {
						struct in6_addr addr, peer_addr;
						if (a->prefix_len == 128) {
							memcpy(addr.s6_addr, &a->addr, 8);
							memcpy(addr.s6_addr + 8, &ses->ipv6->intf_id, 8);
							memcpy(peer_addr.s6_addr, &a->addr, 8);
							memcpy(peer_addr.s6_addr + 8, &ses->ipv6->peer_intf_id, 8);
							ip6addr_add_peer(ses->ifindex, &addr, &peer_addr);
						} else {
							build_ip6_addr(a, ses->ipv6->intf_id, &addr);
							if (memcmp(&addr, &ia_addr->addr, sizeof(addr)) == 0)
								build_ip6_addr(a, ~ses->ipv6->intf_id, &addr);
							ip6addr_add(ses->ifindex, &addr, a->prefix_len);
						}
						a->installed = 1;
					}
				}

				if (code == D6_REPLY) {
					list_for_each_entry(opt2, &opt->opt_list, entry) {
						if (ntohs(opt2->hdr->code) == D6_OPTION_IAADDR) {
							ia_addr = (struct dhcpv6_opt_ia_addr *)opt2->hdr;

							if (IN6_IS_ADDR_UNSPECIFIED(&ia_addr->addr))
								continue;

							f1 = 0;
							list_for_each_entry(a, &ses->ipv6->addr_list, entry) {
								build_ip6_addr(a, ses->ipv6->peer_intf_id, &addr);
								if (memcmp(&addr, &ia_addr->addr, sizeof(addr)))
									continue;
								f1 = 1;
								break;
							}

							if (!f1) {
								opt3 = dhcpv6_nested_option_alloc(reply, opt1, D6_OPTION_IAADDR, sizeof(*ia_addr) - sizeof(struct dhcpv6_opt_hdr));
								memcpy(opt3->hdr->data, opt2->hdr->data, sizeof(*ia_addr) - sizeof(struct dhcpv6_opt_hdr));

								ia_addr = (struct dhcpv6_opt_ia_addr *)opt3->hdr;
								ia_addr->pref_lifetime = 0;
								ia_addr->valid_lifetime = 0;

								insert_status(reply, opt3, D6_STATUS_NotOnLink);
							}
						}
					}
				}

				//insert_status(reply, opt1, D6_STATUS_Success);
			}

		// IA_PD
		} else if (ntohs(opt->hdr->code) == D6_OPTION_IA_PD) {
			if (req->hdr->type == D6_INFORMATION_REQUEST)
				continue;

			opt1 = dhcpv6_option_alloc(reply, D6_OPTION_IA_PD, sizeof(struct dhcpv6_opt_ia_na) - sizeof(struct dhcpv6_opt_hdr));
			memcpy(opt1->hdr + 1, opt->hdr + 1, ntohs(opt1->hdr->len));

			ia_na = (struct dhcpv6_opt_ia_na *)opt1->hdr;
			ia_na->T1 = conf_pref_lifetime == -1 ? -1 : htonl(conf_pref_lifetime / 2);
			ia_na->T2 = conf_pref_lifetime == -1 ? -1 : htonl((conf_pref_lifetime * 4) / 5);

			if (!ses->ipv6_dp) {
				ses->ipv6_dp = ipdb_get_ipv6_prefix(ses);
				if (ses->ipv6_dp)
					triton_event_fire(EV_FORCE_INTERIM_UPDATE, ses);
			}

			if ((req->hdr->type == D6_RENEW) && pd->dp_iaid != ia_na->iaid) {
				insert_status(reply, opt1, D6_STATUS_NoBinding);
			} else if (!ses->ipv6_dp || list_empty(&ses->ipv6_dp->prefix_list) || f2) {
				insert_status(reply, opt1, D6_STATUS_NoPrefixAvail);
			} else {

				if (req->hdr->type == D6_REQUEST || req->rapid_commit) {
					pd->dp_iaid = ia_na->iaid;
					if (!pd->dp_active)
						insert_dp_routes(ses, pd, &req->addr.sin6_addr);
				}

				f2 = 1;

				list_for_each_entry(a, &ses->ipv6_dp->prefix_list, entry) {
					opt2 = dhcpv6_nested_option_alloc(reply, opt1, D6_OPTION_IAPREFIX, sizeof(*ia_prefix) - sizeof(struct dhcpv6_opt_hdr));
					ia_prefix = (struct dhcpv6_opt_ia_prefix *)opt2->hdr;

					memcpy(&ia_prefix->prefix, &a->addr, sizeof(a->addr));
					ia_prefix->prefix_len = a->prefix_len;
					ia_prefix->pref_lifetime = htonl(conf_pref_lifetime);
					ia_prefix->valid_lifetime = htonl(conf_valid_lifetime);
				}

				if (code == D6_REPLY) {
					list_for_each_entry(opt2, &opt->opt_list, entry) {
						if (ntohs(opt2->hdr->code) == D6_OPTION_IAPREFIX) {
							ia_prefix = (struct dhcpv6_opt_ia_prefix *)opt2->hdr;

							if (ia_prefix->prefix_len == 0 || IN6_IS_ADDR_UNSPECIFIED(&ia_prefix->prefix))
								continue;

							f1 = 0;
							list_for_each_entry(a, &ses->ipv6_dp->prefix_list, entry) {
								if (a->prefix_len != ia_prefix->prefix_len)
									continue;
								if (memcmp(&a->addr, &ia_prefix->prefix, sizeof(a->addr)))
									continue;
								f1 = 1;
								break;
							}

							if (!f1) {
								opt3 = dhcpv6_nested_option_alloc(reply, opt1, D6_OPTION_IAPREFIX, sizeof(*ia_prefix) - sizeof(struct dhcpv6_opt_hdr));
								memcpy(opt3->hdr->data, opt2->hdr->data, sizeof(*ia_prefix) - sizeof(struct dhcpv6_opt_hdr));
								ia_prefix = (struct dhcpv6_opt_ia_prefix *)opt3->hdr;
								ia_prefix->pref_lifetime = 0;
								ia_prefix->valid_lifetime = 0;

								insert_status(reply, opt3, D6_STATUS_NotOnLink);
							}
						}
					}
				}

				//insert_status(reply, opt1, D6_STATUS_Success);
		}

		// IA_TA
		} else if (ntohs(opt->hdr->code) == D6_OPTION_IA_TA) {
			if (req->hdr->type == D6_INFORMATION_REQUEST)
				continue;

			opt1 = dhcpv6_option_alloc(reply, D6_OPTION_IA_TA, sizeof(struct dhcpv6_opt_ia_ta) - sizeof(struct dhcpv6_opt_hdr));
			memcpy(opt1->hdr + 1, opt->hdr + 1, ntohs(opt1->hdr->len));

			insert_status(reply, opt1, D6_STATUS_NoAddrsAvail);

		// Option Request
		} else if (ntohs(opt->hdr->code) == D6_OPTION_ORO) {
			insert_oro(reply, opt);

		} else if (ntohs(opt->hdr->code) == D6_OPTION_RAPID_COMMIT) {
			if (req->hdr->type == D6_SOLICIT)
				dhcpv6_option_alloc(reply, D6_OPTION_RAPID_COMMIT, 0);
		}
	}

	opt1 = dhcpv6_option_alloc(reply, D6_OPTION_PREFERENCE, 1);
	*(uint8_t *)opt1->hdr->data = 255;

	//insert_status(reply, NULL, D6_STATUS_Success);

	if (conf_verbose) {
		log_ppp_info2("send ");
		dhcpv6_packet_print(reply, log_ppp_info2);
	}

	dhcpv6_fill_relay_info(reply);

	net->sendto(pd->hnd.fd, reply->hdr, reply->endptr - (void *)reply->hdr, 0, (struct sockaddr *)&req->addr, sizeof(req->addr));

	dhcpv6_packet_free(reply);
}

static void dhcpv6_send_reply2(struct dhcpv6_packet *req, struct dhcpv6_pd *pd, int code)
{
	struct dhcpv6_packet *reply;
	struct dhcpv6_option *opt, *opt1, *opt2, *opt3;
	struct dhcpv6_opt_ia_na *ia_na;
	struct dhcpv6_opt_ia_addr *ia_addr;
	struct dhcpv6_opt_ia_prefix *ia_prefix;
	struct ipv6db_addr_t *a;
	struct in6_addr addr;
	struct ap_session *ses = req->ses;
	int f = 0, f1, f2 = 0, f3;

	reply = dhcpv6_packet_alloc_reply(req, code);
	if (!reply)
		return;

	list_for_each_entry(opt, &req->opt_list, entry) {

		// IA_NA
		if (ntohs(opt->hdr->code) == D6_OPTION_IA_NA) {
			opt1 = dhcpv6_option_alloc(reply, D6_OPTION_IA_NA, sizeof(struct dhcpv6_opt_ia_na) - sizeof(struct dhcpv6_opt_hdr));
			memcpy(opt1->hdr + 1, opt->hdr + 1, ntohs(opt1->hdr->len));

			ia_na = (struct dhcpv6_opt_ia_na *)opt1->hdr;
			ia_na->T1 = conf_pref_lifetime == -1 ? -1 : htonl(conf_pref_lifetime / 2);
			ia_na->T2 = conf_pref_lifetime == -1 ? -1 : htonl((conf_pref_lifetime * 4) / 5);

			f3 = 0;

			list_for_each_entry(opt2, &opt->opt_list, entry) {
				if (ntohs(opt2->hdr->code) == D6_OPTION_IAADDR) {
					ia_addr = (struct dhcpv6_opt_ia_addr *)opt2->hdr;

					if (IN6_IS_ADDR_UNSPECIFIED(&ia_addr->addr))
						continue;

					f1 = 0;

					if (!f) {
						list_for_each_entry(a, &ses->ipv6->addr_list, entry) {
							build_ip6_addr(a, ses->ipv6->peer_intf_id, &addr);
							if (memcmp(&addr, &ia_addr->addr, sizeof(addr)))
								continue;
							f1 = 1;
							f3 = 1;
							break;
						}
					}

					opt3 = dhcpv6_nested_option_alloc(reply, opt1, D6_OPTION_IAADDR, sizeof(*ia_addr) - sizeof(struct dhcpv6_opt_hdr));
					memcpy(opt3->hdr->data, opt2->hdr->data, sizeof(*ia_addr) - sizeof(struct dhcpv6_opt_hdr));

					ia_addr = (struct dhcpv6_opt_ia_addr *)opt3->hdr;
					if (f1) {
						ia_addr->pref_lifetime = htonl(conf_pref_lifetime);
						ia_addr->valid_lifetime = htonl(conf_valid_lifetime);
					} else {
						ia_addr->pref_lifetime = 0;
						ia_addr->valid_lifetime = 0;

						goto out;
					}
				}
			}

			if (f3) {
				pd->addr_iaid = ia_na->iaid;
				f = 1;
			}


		// IA_PD
		} else if (ntohs(opt->hdr->code) == D6_OPTION_IA_PD) {
			opt1 = dhcpv6_option_alloc(reply, D6_OPTION_IA_PD, sizeof(struct dhcpv6_opt_ia_na) - sizeof(struct dhcpv6_opt_hdr));
			memcpy(opt1->hdr + 1, opt->hdr + 1, ntohs(opt1->hdr->len));

			ia_na = (struct dhcpv6_opt_ia_na *)opt1->hdr;
			ia_na->T1 = conf_pref_lifetime == -1 ? -1 : htonl(conf_pref_lifetime / 2);
			ia_na->T2 = conf_pref_lifetime == -1 ? -1 : htonl((conf_pref_lifetime * 4) / 5);

			if (!ses->ipv6_dp) {
				ses->ipv6_dp = ipdb_get_ipv6_prefix(ses);
				if (ses->ipv6_dp)
					triton_event_fire(EV_FORCE_INTERIM_UPDATE, ses);
			}

			if (!ses->ipv6_dp)
				goto out;

			f3 = 0;

			list_for_each_entry(opt2, &opt->opt_list, entry) {
				if (ntohs(opt2->hdr->code) == D6_OPTION_IAPREFIX) {
					ia_prefix = (struct dhcpv6_opt_ia_prefix *)opt2->hdr;

					if (ia_prefix->prefix_len == 0 || IN6_IS_ADDR_UNSPECIFIED(&ia_prefix->prefix))
						continue;

					f1 = 0;

					if (!f2) {
						list_for_each_entry(a, &ses->ipv6_dp->prefix_list, entry) {
							if (a->prefix_len != ia_prefix->prefix_len)
								continue;
							if (memcmp(&a->addr, &ia_prefix->prefix, sizeof(a->addr)))
								continue;
							f1 = 1;
							f3 = 1;
							break;
						}
					}

					opt3 = dhcpv6_nested_option_alloc(reply, opt1, D6_OPTION_IAPREFIX, sizeof(*ia_prefix) - sizeof(struct dhcpv6_opt_hdr));
					memcpy(opt3->hdr->data, opt2->hdr->data, sizeof(*ia_prefix) - sizeof(struct dhcpv6_opt_hdr));
					ia_prefix = (struct dhcpv6_opt_ia_prefix *)opt3->hdr;

					if (f1) {
						ia_prefix->pref_lifetime = htonl(conf_pref_lifetime);
						ia_prefix->valid_lifetime = htonl(conf_valid_lifetime);
					} else {
						ia_prefix->pref_lifetime = 0;
						ia_prefix->valid_lifetime = 0;

						goto out;
					}
				}
			}

			if (f3) {
				pd->dp_iaid = ia_na->iaid;
				f2 = 1;
			}
		// Option Request
		} else if (ntohs(opt->hdr->code) == D6_OPTION_ORO)
			insert_oro(reply, opt);
	}

	opt1 = dhcpv6_option_alloc(reply, D6_OPTION_PREFERENCE, 1);
	*(uint8_t *)opt1->hdr->data = 255;

	//insert_status(reply, NULL, D6_STATUS_Success);

	if (conf_verbose) {
		log_ppp_info2("send ");
		dhcpv6_packet_print(reply, log_ppp_info2);
	}

	dhcpv6_fill_relay_info(reply);

	net->sendto(pd->hnd.fd, reply->hdr, reply->endptr - (void *)reply->hdr, 0, (struct sockaddr *)&req->addr, sizeof(req->addr));

out:
	dhcpv6_packet_free(reply);
}


static void dhcpv6_recv_solicit(struct dhcpv6_packet *req)
{
	struct dhcpv6_pd *pd = req->pd;

	if (!req->clientid) {
		log_ppp_error("dhcpv6: no Client-ID option\n");
		return;
	}

	if (req->serverid) {
		log_ppp_error("dhcpv6: unexpected Server-ID option\n");
		return;
	}

	req->serverid = conf_serverid;

	if (req->rapid_commit) {
		if (!pd->clientid) {
			pd->clientid = _malloc(sizeof(struct dhcpv6_opt_hdr) + ntohs(req->clientid->hdr.len));
			memcpy(pd->clientid, req->clientid, sizeof(struct dhcpv6_opt_hdr) + ntohs(req->clientid->hdr.len));
		} else if (pd->clientid->hdr.len != req->clientid->hdr.len || memcmp(pd->clientid, req->clientid, sizeof(struct dhcpv6_opt_hdr) + ntohs(req->clientid->hdr.len))) {
			log_ppp_error("dhcpv6: unmatched Client-ID option\n");
			return;
		}
	}

	dhcpv6_send_reply(req, pd, req->rapid_commit ? D6_REPLY : D6_ADVERTISE);
}

static void dhcpv6_recv_request(struct dhcpv6_packet *req)
{
	struct dhcpv6_pd *pd = req->pd;

	if (!req->clientid) {
		log_ppp_error("dhcpv6: no Client-ID option\n");
		return;
	}

	if (!req->serverid) {
		log_ppp_error("dhcpv6: no Server-ID option\n");
		return;
	}

	if (!pd->clientid) {
		pd->clientid = _malloc(sizeof(struct dhcpv6_opt_hdr) + ntohs(req->clientid->hdr.len));
		memcpy(pd->clientid, req->clientid, sizeof(struct dhcpv6_opt_hdr) + ntohs(req->clientid->hdr.len));
	} else if (pd->clientid->hdr.len != req->clientid->hdr.len || memcmp(pd->clientid, req->clientid, sizeof(struct dhcpv6_opt_hdr) + ntohs(req->clientid->hdr.len))) {
		log_ppp_error("dhcpv6: unmatched Client-ID option\n");
		return;
	}

	dhcpv6_send_reply(req, pd, D6_REPLY);
}

static void dhcpv6_recv_renew(struct dhcpv6_packet *req)
{
	struct dhcpv6_pd *pd = req->pd;

	if (!req->clientid) {
		log_ppp_error("dhcpv6: no Client-ID option\n");
		return;
	}

	if (!req->serverid) {
		log_ppp_error("dhcpv6: no Server-ID option\n");
		return;
	}

	if (req->serverid->hdr.len != conf_serverid->hdr.len ||
		memcmp(req->serverid, conf_serverid, ntohs(conf_serverid->hdr.len) + sizeof(struct dhcpv6_opt_hdr))) {
		log_ppp_error("dhcpv6: unmatched Server-ID option\n");
		return;
	}

	if (!pd->clientid) {
		log_ppp_error("dhcpv6: no Request was received\n");
		return;
	}

	if (req->clientid->hdr.len != pd->clientid->hdr.len ||
		memcmp(req->clientid, pd->clientid, ntohs(pd->clientid->hdr.len) + sizeof(struct dhcpv6_opt_hdr))) {
		log_ppp_error("dhcpv6: unmatched Client-ID option\n");
		return;
	}

	dhcpv6_send_reply(req, pd, D6_REPLY);
}

static void dhcpv6_recv_information_request(struct dhcpv6_packet *req)
{
	struct dhcpv6_pd *pd = req->pd;

	if (req->rapid_commit) {
		log_ppp_error("dhcpv6: unexpected Rapid-Commit option\n");
		return;
	}

	req->serverid = conf_serverid;

	dhcpv6_send_reply(req, pd, D6_REPLY);
}

static void dhcpv6_recv_rebind(struct dhcpv6_packet *req)
{
	struct dhcpv6_pd *pd = req->pd;

	if (!req->clientid) {
		log_ppp_error("dhcpv6: no Client-ID option\n");
		return;
	}

	if (req->serverid) {
		log_ppp_error("dhcpv6: unexcpected Server-ID option\n");
		return;
	}

	if (!pd->clientid)
		return;
	else if (pd->clientid->hdr.len != req->clientid->hdr.len || memcmp(pd->clientid, req->clientid, sizeof(struct dhcpv6_opt_hdr) + ntohs(req->clientid->hdr.len))) {
		log_ppp_error("dhcpv6: unmatched Client-ID option\n");
		return;
	}

	req->serverid = conf_serverid;

	dhcpv6_send_reply2(req, pd, D6_REPLY);
}

static void dhcpv6_recv_release(struct dhcpv6_packet *pkt)
{
	// don't answer
}

static void dhcpv6_recv_decline(struct dhcpv6_packet *pkt)
{
	// don't answer
}


static void dhcpv6_recv_packet(struct dhcpv6_packet *pkt)
{
	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv6_packet_print(pkt, log_ppp_info2);
	}

	switch (pkt->hdr->type) {
		case D6_SOLICIT:
			dhcpv6_recv_solicit(pkt);
			break;
		case D6_REQUEST:
			dhcpv6_recv_request(pkt);
			break;
		case D6_RENEW:
			dhcpv6_recv_renew(pkt);
			break;
		case D6_REBIND:
			dhcpv6_recv_rebind(pkt);
			break;
		case D6_RELEASE:
			dhcpv6_recv_release(pkt);
			break;
		case D6_DECLINE:
			dhcpv6_recv_decline(pkt);
			break;
		case D6_INFORMATION_REQUEST:
			dhcpv6_recv_information_request(pkt);
			break;
	}

	dhcpv6_packet_free(pkt);
}

static int dhcpv6_read(struct triton_md_handler_t *h)
{
	struct dhcpv6_pd *pd = container_of(h, typeof(*pd), hnd);
	struct ap_session *ses = pd->ses;
	int n;
	struct sockaddr_in6 addr;
	socklen_t len = sizeof(addr);
	struct dhcpv6_packet *pkt;
	uint8_t *buf = _malloc(BUF_SIZE);

	while (1) {
		n = net->recvfrom(h->fd, buf, BUF_SIZE, 0, (struct sockaddr *)&addr, &len);
		if (n == -1) {
			if (errno == EAGAIN)
				break;
			log_error("dhcpv6: read: %s\n", strerror(errno));
			continue;
		}

		if (!IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr))
			continue;

		if (addr.sin6_port != ntohs(DHCPV6_CLIENT_PORT))
			continue;

		pkt = dhcpv6_packet_parse(buf, n);
		if (!pkt || !pkt->clientid) {
			continue;
		}

		pkt->ses = ses;
		pkt->pd = pd;
		pkt->addr = addr;

		dhcpv6_recv_packet(pkt);
	}

	_free(buf);

	return 0;
}

static void add_dnssl(const char *val)
{
	int n;
	const char *ptr;
	uint8_t *buf;

	if (!val)
		return;
	n = strlen(val);

	if (val[n - 1] == '.')
		n++;
	else
		n += 2;

	if (n > 255) {
		log_error("dnsv6: dnssl '%s' is too long\n", val);
		return;
	}

	if (!conf_dnssl)
		conf_dnssl = _malloc(n);
	else
		conf_dnssl = _realloc(conf_dnssl, conf_dnssl_size + n);

	buf = conf_dnssl + conf_dnssl_size;

	while (1) {
		ptr = strchr(val, '.');
		if (!ptr)
			ptr = strchr(val, 0);
		if (ptr - val > 63) {
			log_error("dnsv6: dnssl '%s' is invalid\n", val);
			return;
		}
		*buf = ptr - val;
		memcpy(buf + 1, val, ptr - val);
		buf += 1 + (ptr - val);
		val = ptr + 1;
		if (!*ptr || !*val) {
				*buf = 0;
				break;
		}
	}

	conf_dnssl_size += n;
}

static void load_dns(void)
{
	struct conf_sect_t *s = conf_get_section("ipv6-dns");
	struct conf_option_t *opt;

	if (!s)
		return;

	conf_dns_count = 0;

	if (conf_dnssl)
		_free(conf_dnssl);
	conf_dnssl = NULL;
	conf_dnssl_size = 0;

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "dnssl")) {
			add_dnssl(opt->val);
			continue;
		}

		if (!strcmp(opt->name, "dns") || !opt->val) {
			if (conf_dns_count == MAX_DNS_COUNT)
				continue;

			if (inet_pton(AF_INET6, opt->val ? opt->val : opt->name, &conf_dns[conf_dns_count]) == 0) {
				log_error("dnsv6: failed to parse '%s'\n", opt->name);
				continue;
			}
			conf_dns_count++;
		}
	}
}

static uint64_t parse_serverid(const char *opt)
{
	union {
		uint64_t u64;
		uint16_t u16[4];
	} __packed u;

	unsigned int n[4];
	int i;

	if (sscanf(opt, "%x:%x:%x:%x", &n[0], &n[1], &n[2], &n[3]) != 4)
		goto err;

	for (i = 0; i < 4; i++) {
		if (n[i] > 0xffff)
			goto err;
		u.u16[i] = htons(n[i]);
	}

	return u.u64;

err:
	log_error("dhcpv6: failed to parse server-id '%s'\n", opt);
	return 0;
}

static void load_config(void)
{
	const char *opt;
	uint64_t id;

	opt = conf_get_opt("ipv6-dhcp", "verbose");
	if (opt)
		conf_verbose = atoi(opt);

	opt = conf_get_opt("ipv6-dhcp", "pref-lifetime");
	if (opt)
		conf_pref_lifetime = atoi(opt);

	opt = conf_get_opt("ipv6-dhcp", "valid-lifetime");
	if (opt)
		conf_valid_lifetime = atoi(opt);

	opt = conf_get_opt("ipv6-dhcp", "route-via-gw");
	if (opt)
		conf_route_via_gw = atoi(opt);

	opt = conf_get_opt("ipv6-dhcp", "server-id");
	if (opt)
		id = parse_serverid(opt);
	else
		id = htobe64(1);

	conf_serverid->hdr.code = htons(D6_OPTION_SERVERID);
	conf_serverid->hdr.len = htons(12);
	conf_serverid->duid.type = htons(DUID_LL);
	conf_serverid->duid.u.ll.htype = htons(27);
	//conf_serverid.duid.u.llt.time = htonl(t - t0);
	memcpy(conf_serverid->duid.u.ll.addr, &id, sizeof(id));

	load_dns();

}

static void init(void)
{
	if (!triton_module_loaded("ipv6_nd"))
		log_warn("dhcpv6: ipv6_nd module is not loaded, you probably get misconfigured network environment\n");

	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
	triton_event_register_handler(EV_SES_STARTED, (triton_event_func)ev_ses_started);
	triton_event_register_handler(EV_SES_FINISHED, (triton_event_func)ev_ses_finished);
}

DEFINE_INIT(10, init);
