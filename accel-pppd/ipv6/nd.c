#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "log.h"
#include "ppp.h"
#include "events.h"
#include "mempool.h"
#include "ipdb.h"
#include "iputils.h"

#include "memdebug.h"

#define MAX_DNS_COUNT 3

static int conf_init_ra = 5;
static int conf_init_ra_interval = 3;
static int conf_rdnss_lifetime;
static struct in6_addr conf_dns[MAX_DNS_COUNT];
static int conf_dns_count;
static uint8_t *conf_dnssl;
static int conf_dnssl_size;

static int conf_MaxRtrAdvInterval = 600;
static int conf_MinRtrAdvInterval;
static int conf_AdvManagedFlag;
static int conf_AdvOtherConfigFlag;
static int conf_AdvLinkMTU;
static int conf_AdvReachableTime;
static int conf_AdvRetransTimer;
static int conf_AdvCurHopLimit = 64;
static int conf_AdvDefaultLifetime;
static int conf_AdvPrefixValidLifetime = 2592000;
static int conf_AdvPrefixPreferredLifetime = 604800;
static int conf_AdvPrefixOnLinkFlag;
static int conf_AdvPrefixAutonomousFlag;


#undef ND_OPT_ROUTE_INFORMATION
#define  ND_OPT_ROUTE_INFORMATION	24
struct nd_opt_route_info_local     /* route information */
{
	uint8_t   nd_opt_ri_type;
	uint8_t   nd_opt_ri_len;
	uint8_t   nd_opt_ri_prefix_len;
	uint8_t   nd_opt_ri_flags_reserved;
	uint32_t  nd_opt_ri_lifetime;
	struct in6_addr  nd_opt_ri_prefix;
};

#undef ND_OPT_RDNSS_INFORMATION
#define  ND_OPT_RDNSS_INFORMATION	25
struct nd_opt_rdnss_info_local
{
	uint8_t  nd_opt_rdnssi_type;
	uint8_t  nd_opt_rdnssi_len;
	uint16_t nd_opt_rdnssi_pref_flag_reserved;
	uint32_t nd_opt_rdnssi_lifetime;
	struct in6_addr  nd_opt_rdnssi[0];
};

#undef ND_OPT_DNSSL_INFORMATION
#define  ND_OPT_DNSSL_INFORMATION	31
struct nd_opt_dnssl_info_local
{
	uint8_t  nd_opt_dnssli_type;
	uint8_t  nd_opt_dnssli_len;
	uint16_t nd_opt_dnssli_pref_flag_reserved;
	uint32_t nd_opt_dnssli_lifetime;
	uint8_t  nd_opt_dnssli[0];
};

struct ipv6_nd_handler_t
{
	struct ap_session *ses;
	struct ap_private pd;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timer;
	int ra_sent;
};

static void *pd_key;

#define BUF_SIZE 1024
static mempool_t buf_pool;

static void ipv6_nd_send_ra(struct ipv6_nd_handler_t *h, struct sockaddr_in6 *dst_addr)
{
	struct ap_session *ses = h->ses;
	void *buf = mempool_alloc(buf_pool), *endptr;
	struct nd_router_advert *adv = buf;
	struct nd_opt_prefix_info *pinfo;
	//struct nd_opt_route_info_local *rinfo;
	struct nd_opt_rdnss_info_local *rdnssinfo;
	struct in6_addr *rdnss_addr;
	struct nd_opt_dnssl_info_local *dnsslinfo;
	//struct nd_opt_mtu *mtu;
	struct ipv6db_addr_t *a;
	struct in6_addr addr, peer_addr;
	int i, prefix_len;

	if (!buf) {
		log_emerg("out of memory\n");
		return;
	}

	if (!ses->ipv6) {
		triton_timer_del(&h->timer);
		return;
	}

	memset(adv, 0, sizeof(*adv));
	adv->nd_ra_type = ND_ROUTER_ADVERT;
	adv->nd_ra_curhoplimit = conf_AdvCurHopLimit;
	adv->nd_ra_router_lifetime = htons(conf_AdvDefaultLifetime);
	adv->nd_ra_flags_reserved =
		(conf_AdvManagedFlag ? ND_RA_FLAG_MANAGED : 0) |
		(conf_AdvOtherConfigFlag ? ND_RA_FLAG_OTHER : 0);
	adv->nd_ra_reachable = htonl(conf_AdvReachableTime);
	adv->nd_ra_retransmit = htonl(conf_AdvRetransTimer);

	pinfo = (struct nd_opt_prefix_info *)(adv + 1);
	list_for_each_entry(a, &ses->ipv6->addr_list, entry) {
		prefix_len = a->prefix_len == 128 ? 64 : a->prefix_len;
		memset(pinfo, 0, sizeof(*pinfo));
		pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		pinfo->nd_opt_pi_len = 4;
		pinfo->nd_opt_pi_prefix_len = prefix_len;
		pinfo->nd_opt_pi_flags_reserved =
			((a->flag_onlink || conf_AdvPrefixOnLinkFlag) ? ND_OPT_PI_FLAG_ONLINK : 0) |
			((a->flag_auto || (conf_AdvPrefixAutonomousFlag && prefix_len == 64)) ? ND_OPT_PI_FLAG_AUTO : 0);
		pinfo->nd_opt_pi_valid_time = htonl(conf_AdvPrefixValidLifetime);
		pinfo->nd_opt_pi_preferred_time = htonl(conf_AdvPrefixPreferredLifetime);
		memcpy(&pinfo->nd_opt_pi_prefix, &a->addr, (prefix_len + 7) / 8);
		pinfo->nd_opt_pi_prefix.s6_addr[prefix_len / 8] &= ~(0xff >> (prefix_len % 8));
		pinfo++;

		if (!a->installed) {
			if (a->prefix_len == 128) {
				memcpy(addr.s6_addr, &a->addr, 8);
				memcpy(addr.s6_addr + 8, &ses->ipv6->intf_id, 8);
				memcpy(peer_addr.s6_addr, &a->addr, 8);
				memcpy(peer_addr.s6_addr + 8, &ses->ipv6->peer_intf_id, 8);
				ip6addr_add_peer(ses->ifindex, &addr, &peer_addr);
			} else {
				build_ip6_addr(a, ses->ipv6->intf_id, &addr);
				build_ip6_addr(a, ses->ipv6->peer_intf_id, &peer_addr);
				if (memcmp(&addr, &peer_addr, sizeof(addr)) == 0)
					build_ip6_addr(a, ~ses->ipv6->intf_id, &addr);
				ip6addr_add(ses->ifindex, &addr, a->prefix_len);
			}
			a->installed = 1;
		}
	}

	/*rinfo = (struct nd_opt_route_info_local *)pinfo;
	list_for_each_entry(a, &h->ses->ipv6->route_list, entry) {
		memset(rinfo, 0, sizeof(*rinfo));
		rinfo->nd_opt_ri_type = ND_OPT_ROUTE_INFORMATION;
		rinfo->nd_opt_ri_len = 3;
		rinfo->nd_opt_ri_prefix_len = a->prefix_len;
		rinfo->nd_opt_ri_lifetime = 0xffffffff;
		memcpy(&rinfo->nd_opt_ri_prefix, &a->addr, 8);
		rinfo++;
	}*/

	if (conf_dns_count) {
		rdnssinfo = (struct nd_opt_rdnss_info_local *)pinfo;
		memset(rdnssinfo, 0, sizeof(*rdnssinfo));
		rdnssinfo->nd_opt_rdnssi_type = ND_OPT_RDNSS_INFORMATION;
		rdnssinfo->nd_opt_rdnssi_len = 1 + 2 * conf_dns_count;
		rdnssinfo->nd_opt_rdnssi_lifetime = htonl(conf_rdnss_lifetime);
		rdnss_addr = (struct in6_addr *)rdnssinfo->nd_opt_rdnssi;
		for (i = 0; i < conf_dns_count; i++) {
			memcpy(rdnss_addr, &conf_dns[i], sizeof(*rdnss_addr));
			rdnss_addr++;
		}
	} else
		rdnss_addr = (struct in6_addr *)pinfo;

	if (conf_dnssl) {
		dnsslinfo = (struct nd_opt_dnssl_info_local *)rdnss_addr;
		memset(dnsslinfo, 0, sizeof(*dnsslinfo));
		dnsslinfo->nd_opt_dnssli_type = ND_OPT_DNSSL_INFORMATION;
		dnsslinfo->nd_opt_dnssli_len = 1 + (conf_dnssl_size - 1) / 8 + 1;
		dnsslinfo->nd_opt_dnssli_lifetime = htonl(conf_rdnss_lifetime);
		memcpy(dnsslinfo->nd_opt_dnssli, conf_dnssl, conf_dnssl_size);
		memset(dnsslinfo->nd_opt_dnssli + conf_dnssl_size, 0, (dnsslinfo->nd_opt_dnssli_len - 1) * 8 - conf_dnssl_size);
		endptr = (uint8_t *)dnsslinfo + dnsslinfo->nd_opt_dnssli_len * 8;
	} else
		endptr = rdnss_addr;

	net->sendto(h->hnd.fd, buf, endptr - buf, 0, (struct sockaddr *)dst_addr, sizeof(*dst_addr));

	mempool_free(buf);
}

static void send_ra_timer(struct triton_timer_t *t)
{
	struct ipv6_nd_handler_t *h = container_of(t, typeof(*h), timer);
	struct sockaddr_in6 addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr.s6_addr32[0] = htonl(0xff020000);
	addr.sin6_addr.s6_addr32[3] = htonl(0x1);
	addr.sin6_scope_id = h->ses->ifindex;

	if (h->ra_sent == conf_init_ra) {
		h->timer.period = conf_MaxRtrAdvInterval * 1000;
		h->timer.period -= (conf_MaxRtrAdvInterval - conf_MinRtrAdvInterval) * random() * 1000 / RAND_MAX;
		triton_timer_mod(t, 0);
	} else
		h->ra_sent++;

	ipv6_nd_send_ra(h, &addr);
}

static int ipv6_nd_read(struct triton_md_handler_t *_h)
{
	struct ipv6_nd_handler_t *h = container_of(_h, typeof(*h), hnd);
	struct icmp6_hdr *icmph = mempool_alloc(buf_pool);
	int n;
	struct sockaddr_in6 addr;
	socklen_t addr_len = sizeof(addr);

	if (!icmph) {
		log_emerg("out of memory\n");
		return 0;
	}

	while (1) {
		n = net->recvfrom(h->hnd.fd, icmph, BUF_SIZE, 0, (struct sockaddr *)&addr, &addr_len);
		if (n == -1) {
			if (errno == EAGAIN)
				break;
			log_ppp_error("ipv6_nd: recvmsg: %s\n", strerror(errno));
			continue;
		}

		if (n < sizeof(*icmph)) {
			log_ppp_warn("ipv6_nd: received short icmp packet (%i)\n", n);
			continue;
		}

		if (icmph->icmp6_type != ND_ROUTER_SOLICIT) {
			log_ppp_warn("ipv6_nd: received unexcpected icmp packet (%i)\n", icmph->icmp6_type);
			continue;
		}

		if (!IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr)) {
			log_ppp_warn("ipv6_nd: received icmp packet from non link-local address\n");
			continue;
		}

		/*if (*(uint64_t *)(addr.sin6_addr.s6_addr + 8) != *(uint64_t *)(h->ses->ipv6_addr.s6_addr + 8)) {
			log_ppp_warn("ipv6_nd: received icmp packet from unknown address\n");
			continue;
		}*/

		ipv6_nd_send_ra(h, &addr);
	}

	mempool_free(icmph);

	return 0;
}

static int ipv6_nd_start(struct ap_session *ses)
{
	int sock;
	struct icmp6_filter filter;
	struct ipv6_mreq mreq;
	int val;
	struct ipv6_nd_handler_t *h;

	net->enter_ns();
	sock = net->socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	net->exit_ns();

	if (sock < 0) {
		log_ppp_error("socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6): %s\n", strerror(errno));
		return -1;
	}

	if (net->setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ses->ifname, strlen(ses->ifname))) {
		log_ppp_error("ipv6_nd: setsockopt(SO_BINDTODEVICE): %s\n", strerror(errno));
		goto out_err;
	}

	val = 2;
	if (net->setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_CHECKSUM): %s\n", strerror(errno));
		goto out_err;
	}

	val = 255;
	if (net->setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_UNICAST_HOPS): %s\n", strerror(errno));
		goto out_err;
	}

	if (net->setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_MULTICAST_HOPS): %s\n", strerror(errno));
		goto out_err;
	}

	/*val = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_HOPLIMIT): %s\n", strerror(errno));
		goto out_err;
	}*/

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);

	if (net->setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter))) {
		log_ppp_error("ipv6_nd: setsockopt(ICMP6_FILTER): %s\n", strerror(errno));
		goto out_err;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_interface = ses->ifindex;
	mreq.ipv6mr_multiaddr.s6_addr32[0] = htonl(0xff020000);
	mreq.ipv6mr_multiaddr.s6_addr32[3] = htonl(0x2);

	if (net->setsockopt(sock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		log_ppp_error("ipv6_nd: failed to join ipv6 allrouters\n");
		goto out_err;
	}

	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	net->set_nonblocking(sock, 1);

	h = _malloc(sizeof(*h));
	memset(h, 0, sizeof(*h));
	h->ses = ses;
	h->pd.key = &pd_key;
	h->hnd.fd = sock;
	h->hnd.read = ipv6_nd_read;
	h->timer.expire = send_ra_timer;
	h->timer.period = conf_init_ra_interval * 1000;
	list_add_tail(&h->pd.entry, &ses->pd_list);

	triton_md_register_handler(ses->ctrl->ctx, &h->hnd);
	triton_md_enable_handler(&h->hnd, MD_MODE_READ);

	triton_timer_add(ses->ctrl->ctx, &h->timer, 0);
	send_ra_timer(&h->timer);

	return 0;

out_err:
	close(sock);
	return -1;
}

static struct ipv6_nd_handler_t *find_pd(struct ap_session *ses)
{
	struct ap_private *pd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key)
			return container_of(pd, typeof(struct ipv6_nd_handler_t), pd);
	}

	return NULL;
}

static void ev_ses_started(struct ap_session *ses)
{
	struct ipv6db_addr_t *a;

	if (!ses->ipv6)
		return;

	list_for_each_entry(a, &ses->ipv6->addr_list, entry) {
		if (a->prefix_len && !IN6_IS_ADDR_UNSPECIFIED(&a->addr)) {
			ipv6_nd_start(ses);
			break;
		}
	}
}

static void ev_ses_finishing(struct ap_session *ses)
{
	struct ipv6_nd_handler_t *h = find_pd(ses);

	if (!h)
		return;

	if (h->timer.tpd)
		triton_timer_del(&h->timer);

	triton_md_unregister_handler(&h->hnd, 1);

	list_del(&h->pd.entry);

	_free(h);
}

static void add_dnssl(const char *val)
{
	int n = strlen(val);
	const char *ptr;
	uint8_t *buf;

	if (!val)
		return;

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

		if (!strcmp(opt->name, "lifetime")) {
			if (opt->val)
				conf_rdnss_lifetime = atoi(opt->val);
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

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("ipv6-nd", "MaxRtrAdvInterval");
	if (opt)
		conf_MaxRtrAdvInterval = atoi(opt);

	conf_MinRtrAdvInterval = 0.33 * conf_MaxRtrAdvInterval;
	conf_AdvDefaultLifetime = 3 * conf_MaxRtrAdvInterval;

	conf_AdvManagedFlag = triton_module_loaded("ipv6_dhcp");
	conf_AdvOtherConfigFlag = triton_module_loaded("ipv6_dhcp");
	conf_AdvPrefixOnLinkFlag = 1;
	conf_AdvPrefixAutonomousFlag = !conf_AdvManagedFlag;
	conf_rdnss_lifetime = conf_MaxRtrAdvInterval;

	opt = conf_get_opt("ipv6-nd", "MinRtrAdvInterval");
	if (opt)
		conf_MinRtrAdvInterval = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "MaxInitialRtrAdvCount");
	if (opt)
		conf_init_ra = atoi(opt);
	opt = conf_get_opt("ipv6-nd", "MaxInitialRtrAdvInterval");
	if (opt)
		conf_init_ra_interval = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvManagedFlag");
	if (opt)
		conf_AdvManagedFlag = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvOtherConfigFlag");
	if (opt)
		conf_AdvOtherConfigFlag = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvLinkMTU");
	if (opt)
		conf_AdvLinkMTU = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvReachableTime");
	if (opt)
		conf_AdvReachableTime = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvRetransTimer");
	if (opt)
		conf_AdvRetransTimer = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvCurHopLimit");
	if (opt)
		conf_AdvCurHopLimit = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvDefaultLifetime");
	if (opt)
		conf_AdvDefaultLifetime = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvValidLifetime");
	if (opt)
		conf_AdvPrefixValidLifetime = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvPreferredLifetime");
	if (opt)
		conf_AdvPrefixPreferredLifetime = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvOnLinkFlag");
	if (opt)
		conf_AdvPrefixOnLinkFlag = atoi(opt);

	opt = conf_get_opt("ipv6-nd", "AdvAutonomousFlag");
	if (opt)
		conf_AdvPrefixAutonomousFlag = atoi(opt);

	load_dns();
}

static void init(void)
{
	buf_pool = mempool_create(BUF_SIZE);

	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
	triton_event_register_handler(EV_SES_STARTED, (triton_event_func)ev_ses_started);
	triton_event_register_handler(EV_SES_FINISHING, (triton_event_func)ev_ses_finishing);
}

DEFINE_INIT(5, init);
