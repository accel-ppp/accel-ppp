#include <netinet/in.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_link.h>

#include "mempool.h"
#include "events.h"
#include "log.h"
#include "ppp.h"
#include "pwdb.h"
#include "ipdb.h"
#include "ppp_auth.h"
#include "iputils.h"
#include "utils.h"

#include "radius_p.h"
#include "attr_defs.h"
#include "config.h"

#include "memdebug.h"

int conf_max_try = 3;
int conf_timeout = 3;
int conf_acct_timeout = 3;
int conf_acct_delay_time;
char *conf_nas_identifier;
in_addr_t conf_nas_ip_address;
in_addr_t conf_gw_ip_address;
in_addr_t conf_bind;
int conf_verbose;
int conf_interim_verbose;

in_addr_t conf_dm_coa_server;
int conf_dm_coa_port = 3799;
char *conf_dm_coa_secret;
char conf_dm_coa_bind_device[IFNAMSIZ];
unsigned int conf_dm_coa_bind_default;

int conf_sid_in_auth;
int conf_nas_port_id_in_req = 1;
int conf_require_nas_ident;
int conf_acct_interim_interval;
int conf_acct_interim_jitter;

int conf_accounting;
int conf_fail_time;
int conf_req_limit;

static const char *conf_default_realm;
static int conf_default_realm_len;
static int conf_strip_realm;

const char *conf_attr_tunnel_type;

int conf_acct_delay_start;
int conf_blast_protection;
int conf_framed_route_strict;

static LIST_HEAD(sessions);
static pthread_rwlock_t sessions_lock = PTHREAD_RWLOCK_INITIALIZER;

struct dae_allow_range {
	struct list_head entry;
	uint32_t begin;
	uint32_t end;
};

static struct list_head *dae_allow_ranges;
static pthread_rwlock_t dae_allow_lock = PTHREAD_RWLOCK_INITIALIZER;

static void *pd_key;
static struct ipdb_t ipdb;

static mempool_t rpd_pool;
static mempool_t auth_ctx_pool;

static int rad_add_framed_ipv6_route(const char *str, struct radius_pd_t *rpd);

static int ipv4_mask_to_prefix(struct in_addr mask, int *plen)
{
	uint32_t m = ntohl(mask.s_addr);
	uint32_t inv = ~m;
	int p = 0;

	if (inv & (inv + 1))
		return -1;

	while (m & 0x80000000) {
		p++;
		m <<= 1;
	}

	*plen = p;
	return 0;
}

static int parse_framed_route_v4(const char *str, struct framed_route *fr)
{
	const char *ptr;
	size_t len;
	struct in_addr dst;
	struct in_addr gw;
	struct in_addr mask_addr;
	uint8_t plen;
	uint32_t prio;
	uint32_t mask = 0;
	uint32_t addr_hbo;

	// Take a steady breath and skip leading RFC-style spaces so everything starts clean.
	ptr = str + u_parse_spaces(str);

	len = u_parse_ip4cidr(ptr, &dst, &plen);
	if (len) {
		// Happy path: CIDR tells us exactly what we need.
		fr->dst = dst.s_addr;
		fr->mask = plen;
		mask = plen ? (0xffffffffu << (32 - plen)) : 0;
		ptr += len;
	} else {
		// If CIDR didn't show up, we gently switch to plain IPv4 and optional mask.
		len = u_parse_ip4addr(ptr, &dst);
		if (!len)
			return -1;
		fr->dst = dst.s_addr;
		ptr += len;

		if (*ptr == '/') {
			ptr++;
			len = u_parse_ip4addr(ptr, &mask_addr);
			if (len) {
				if (ipv4_mask_to_prefix(mask_addr, &fr->mask))
					return -1;
				mask = ntohl(mask_addr.s_addr);
				ptr += len;
			} else {
				len = u_parse_u8(ptr, &plen);
				if (!len || plen > 32)
					return -1;
				fr->mask = plen;
				mask = plen ? (0xffffffffu << (32 - plen)) : 0;
				ptr += len;
			}
		} else
			fr->mask = 32;
	}

	if (!mask)
		mask = fr->mask ? (0xffffffffu << (32 - fr->mask)) : 0;

	if (conf_framed_route_strict) {
		addr_hbo = ntohl(fr->dst);
		if (addr_hbo & ~mask)
			return -1;
	}

	// If the string ends here, we can relax: no gateway or metric specified.
	ptr += u_parse_spaces(ptr);
	if (u_parse_endstr(ptr)) {
		fr->gw = 0;
		fr->prio = 0;
		return 0;
	}

	len = u_parse_ip4addr(ptr, &gw);
	if (!len)
		return -1;
	fr->gw = gw.s_addr;
	ptr += len;

	ptr += u_parse_spaces(ptr);
	if (u_parse_endstr(ptr)) {
		fr->prio = 0;
		return 0;
	}

	len = u_parse_u32(ptr, &prio);
	if (!len)
		return -1;
	ptr += len;

	if (!u_parse_endstr(ptr))
		return -1;

	fr->prio = prio;
	return 0;
}

static void parse_framed_route(struct radius_pd_t *rpd, const char *attr)
{
	struct framed_route *fr;

	// RFC 2865: Framed-Route is IPv4-only and uses spaces; IPv6 lives in Framed-IPv6-Route.
	if (strchr(attr, ':')) {
		log_ppp_warn("radius: Framed-Route is IPv4-only per RFC 2865, use Framed-IPv6-Route for %s\n", attr);
		return;
	}

	fr = _malloc(sizeof(*fr));
	if (!fr)
		goto out_err;
	memset(fr, 0, sizeof(*fr));

	if (parse_framed_route_v4(attr, fr) < 0)
		goto out_err_free;

	fr->next = rpd->fr;
	rpd->fr = fr;

	return;

out_err_free:
	_free(fr);
out_err:
	log_ppp_warn("radius: failed to parse Framed-Route=%s\n", attr);
}

static char *trim_spaces(char *str)
{
	char *end;

	while (isspace((unsigned char)*str))
		++str;

	if (*str == '\0')
		return str;

	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) {
		*end = '\0';
		--end;
	}

	return str;
}

static void dae_allow_clear(void)
{
	struct dae_allow_range *range;

	if (!dae_allow_ranges)
		return;

	while (!list_empty(dae_allow_ranges)) {
		range = list_first_entry(dae_allow_ranges, typeof(*range), entry);
		list_del(&range->entry);
		_free(range);
	}

	_free(dae_allow_ranges);
	dae_allow_ranges = NULL;
}

static int dae_allow_add(uint32_t begin, uint32_t end)
{
	struct dae_allow_range *range;

	if (!dae_allow_ranges)
		return -1;

	range = _malloc(sizeof(*range));
	if (!range)
		return -1;

	range->begin = begin;
	range->end = end;
	list_add_tail(&range->entry, dae_allow_ranges);

	return 0;
}

static int dae_allow_parse_token(const char *token, uint32_t *begin, uint32_t *end)
{
	struct in_addr base_addr;
	uint8_t suffix;
	size_t len;

	len = u_parse_ip4cidr(token, &base_addr, &suffix);
	if (len && token[len] == '\0') {
		uint32_t addr_hbo = ntohl(base_addr.s_addr);
		uint32_t mask = (uint64_t)0xffffffff << (32 - suffix);
		uint32_t ip_min = addr_hbo & mask;

		*begin = ip_min;
		*end = addr_hbo | ~mask;
		if (ip_min != addr_hbo) {
			struct in_addr min_addr = { .s_addr = htonl(ip_min) };
			char ipbuf[INET_ADDRSTRLEN];

			log_warn("radius: dae-allowed network %s is equivalent to %s/%hhu\n",
				 token, u_ip4str(&min_addr, ipbuf), suffix);
		}
		return 0;
	}

	if (!inet_aton(token, &base_addr))
		return -1;

	*begin = ntohl(base_addr.s_addr);
	*end = *begin;
	return 0;
}

static int dae_allow_parse(const char *opt, int *entries)
{
	char *dup;
	char *token;
	char *saveptr;
	int count = 0;

	dup = _strdup(opt);
	if (!dup)
		return -1;

	for (token = strtok_r(dup, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		char *trimmed = trim_spaces(token);
		uint32_t begin;
		uint32_t end;

		if (*trimmed == '\0')
			continue;

		if (dae_allow_parse_token(trimmed, &begin, &end)) {
			log_warn("radius: dae-allowed invalid entry \"%s\"\n", trimmed);
			continue;
		}

		if (dae_allow_add(begin, end)) {
			_free(dup);
			return -1;
		}

		++count;
	}

	_free(dup);
	*entries = count;
	return 0;
}

static int dae_allow_check(in_addr_t ipaddr)
{
	struct dae_allow_range *range;
	uint32_t addr = ntohl(ipaddr);

	list_for_each_entry(range, dae_allow_ranges, entry) {
		if (addr >= range->begin && addr <= range->end)
			return 0;
	}

	return -1;
}

int rad_dae_src_check(in_addr_t ipaddr)
{
	int res = 0;

	pthread_rwlock_rdlock(&dae_allow_lock);
	if (dae_allow_ranges)
		res = dae_allow_check(ipaddr);
	pthread_rwlock_unlock(&dae_allow_lock);

	return res;
}

/* Parse a RADIUS Framed-IPv6-Route string.
 *
 * Full format is like: "2001:db8::/32 fc00::1 2000"
 *
 *   * "2001:db8::/32" is the network prefix
 *   * "fc00::1" is the gateway address
 *   * "2000" is the route metric (priority)
 *
 * The route metric can be omitted, in which case it is set to 0. This let the
 * kernel use its own default route metric.
 * If the route metric is not set, the gateway address can be omitted too. In
 * this case, it's set to the unspecified address ('::'). This makes the route
 * use the session's network interface directly rather than an IP gateway.
 */
static int parse_framed_ipv6_route(const char *str,
				   struct framed_ip6_route *fr6)
{
	const char *ptr;
	size_t len;

	/* Skip leading spaces */
	ptr = str + u_parse_spaces(str);

	/* Get network prefix and prefix length */
	len = u_parse_ip6cidr(ptr, &fr6->prefix, &fr6->plen);
	if (!len) {
		log_ppp_warn("radius: parsing Framed-IPv6-Route attribute \"%s\" failed at \"%s\":"
			     " expecting an IPv6 network prefix in CIDR notation\n",
			     str, ptr);
		return -1;
	}
	ptr += len;

	/* Check separator, unless string ends here */
	len = u_parse_spaces(ptr);
	if (!len && *ptr != '\0') {
		log_ppp_warn("radius: parsing Framed-IPv6-Route attribute \"%s\" failed at \"%s\":"
			     " missing space after network prefix\n",
			     str, ptr);
		return -1;
	}
	ptr += len;

	/* If end of string, use no gateway and default metric */
	if (*ptr == '\0') {
		fr6->gw = in6addr_any;
		fr6->prio = 0;
		return 0;
	}

	/* Get the gateway address */
	len = u_parse_ip6addr(ptr, &fr6->gw);
	if (!len) {
		log_ppp_warn("radius: parsing Framed-IPv6-Route attribute \"%s\" failed at \"%s\":"
			     " expecting a gateway IPv6 address\n",
			     str, ptr);
		return -1;
	}
	ptr += len;

	/* Again, separator or end of string required */
	len = u_parse_spaces(ptr);
	if (!len && *ptr != '\0') {
		log_ppp_warn("radius: parsing Framed-IPv6-Route attribute \"%s\" failed at \"%s\":"
			     " missing space after gateway address\n",
			     str, ptr);
		return -1;
	}
	ptr += len;

	/* If end of string, use default metric */
	if (*ptr == '\0') {
		fr6->prio = 0;
		return 0;
	}

	/* Get route metric */
	len = u_parse_u32(ptr, &fr6->prio);
	if (!len) {
		log_ppp_warn("radius: parsing Framed-IPv6-Route attribute \"%s\" failed at \"%s\":"
			     " expecting a route metric between 0 and %u\n",
			     str, ptr, UINT32_MAX);
		return -1;
	}
	ptr += len;

	/* Now this must be the end of the string */
	if (!u_parse_endstr(ptr)) {
		log_ppp_warn("radius: parsing Framed-IPv6-Route attribute \"%s\" failed at \"%s\":"
			     " unexpected data after route metric\n",
			     str, ptr + u_parse_spaces(ptr));
		return -1;
	}

	return 0;
}

static int rad_add_framed_ipv6_route(const char *str, struct radius_pd_t *rpd)
{
	struct framed_ip6_route *fr6;

	fr6 = _malloc(sizeof(*fr6));
	if (!fr6)
		goto err;

	if (parse_framed_ipv6_route(str, fr6) < 0)
		goto err_fr6;

	fr6->next = rpd->fr6;
	rpd->fr6 = fr6;

	return 0;

err_fr6:
	_free(fr6);
err:
	return -1;
}

int rad_proc_attrs(struct rad_req_t *req)
{
	struct ev_wins_t wins = {};
	struct ev_dns_t dns = {};
	struct rad_attr_t *attr;
	struct ipv6db_addr_t *a;
	int res = 0;
	struct radius_pd_t *rpd = req->rpd;

	req->rpd->acct_interim_interval = conf_acct_interim_interval;
	req->rpd->acct_interim_jitter = conf_acct_interim_jitter;

	list_for_each_entry(attr, &req->reply->attrs, entry) {
		if (attr->vendor) {
			if (attr->vendor->id == VENDOR_Microsoft) {
				switch (attr->attr->id) {
					case MS_Primary_DNS_Server:
						dns.ses = rpd->ses;
						dns.dns1 = attr->val.ipaddr;
						break;
					case MS_Secondary_DNS_Server:
						dns.ses = rpd->ses;
						dns.dns2 = attr->val.ipaddr;
						break;
					case MS_Primary_NBNS_Server:
						wins.ses = rpd->ses;
						wins.wins1 = attr->val.ipaddr;
						break;
					case MS_Secondary_NBNS_Server:
						wins.ses = rpd->ses;
						wins.wins2 = attr->val.ipaddr;
						break;
				}
				continue;
#ifdef HAVE_VRF
			} else if (attr->vendor->id == VENDOR_Accel_PPP) {
				switch (attr->attr->id) {
					case Accel_VRF_Name:
						if (rpd->ses->vrf_name)
							_free(rpd->ses->vrf_name);
						rpd->ses->vrf_name = _malloc(attr->len + 1);
						memcpy(rpd->ses->vrf_name, attr->val.string, attr->len);
						rpd->ses->vrf_name[attr->len] = 0;
						break;
				}
				continue;
#endif
			}
			continue;
		}

		switch(attr->attr->id) {
			case User_Name:
				if (rpd->acct_username)
					_free(rpd->acct_username);
				if (attr->len)
					rpd->acct_username = _strndup(attr->val.string, attr->len);
				else if (rpd->acct_username)
					rpd->acct_username = NULL;
				break;
			case Framed_IP_Address:
				if (!conf_gw_ip_address && rpd->ses->ctrl->ppp)
					log_ppp_warn("radius: gw-ip-address not specified, cann't assign IP address...\n");
				else if (attr->val.ipaddr != htonl(0xfffffffe)) {
					rpd->ipv4_addr.owner = &ipdb;
					rpd->ipv4_addr.peer_addr = attr->val.ipaddr;
					rpd->ipv4_addr.addr = rpd->ses->ctrl->ppp ? conf_gw_ip_address : 0;
				}
				break;
			case Acct_Interim_Interval:
				rpd->acct_interim_interval = attr->val.integer;
				break;
			case Session_Timeout:
				rpd->session_timeout.expire_tv.tv_sec = attr->val.integer;
				break;
			case Idle_Timeout:
				rpd->ses->idle_timeout = attr->val.integer;
				break;
			case Class:
				if (!rpd->attr_class)
					rpd->attr_class = _malloc(attr->len);
				else if (rpd->attr_class_len != attr->len)
					rpd->attr_class = _realloc(rpd->attr_class, attr->len);
				memcpy(rpd->attr_class, attr->val.octets, attr->len);
				rpd->attr_class_len = attr->len;
				break;
			case State:
				if (!rpd->attr_state)
					rpd->attr_state = _malloc(attr->len);
				else if (rpd->attr_state_len != attr->len)
					rpd->attr_state = _realloc(rpd->attr_state, attr->len);
				memcpy(rpd->attr_state, attr->val.octets, attr->len);
				rpd->attr_state_len = attr->len;
				break;
			case Termination_Action:
				rpd->termination_action = attr->val.integer;
				break;
			case Framed_Interface_Id:
				rpd->ipv6_addr.peer_intf_id = attr->val.ifid;
				break;
			case Framed_IPv6_Prefix:
				a = _malloc(sizeof(*a));
				memset(a, 0, sizeof(*a));
				a->prefix_len = attr->val.ipv6prefix.len;
				a->addr = attr->val.ipv6prefix.prefix;
				list_add_tail(&a->entry, &rpd->ipv6_addr.addr_list);
				break;
			case Delegated_IPv6_Prefix:
				a = _malloc(sizeof(*a));
				memset(a, 0, sizeof(*a));
				a->prefix_len = attr->val.ipv6prefix.len;
				a->addr = attr->val.ipv6prefix.prefix;
				list_add_tail(&a->entry, &rpd->ipv6_dp.prefix_list);
				break;
			case NAS_Port:
				rpd->ses->unit_idx = attr->val.integer;
				break;
			case NAS_Port_Id:
				if (rpd->ses->ifname_rename)
					_free(rpd->ses->ifname_rename);
				rpd->ses->ifname_rename = _malloc(attr->len + 1);
				memcpy(rpd->ses->ifname_rename, attr->val.string, attr->len);
				rpd->ses->ifname_rename[attr->len] = 0;
				break;
			case Framed_Route:
				parse_framed_route(rpd, attr->val.string);
				break;
			case Framed_IPv6_Route:
				rad_add_framed_ipv6_route(attr->val.string, rpd);
				break;
		}
	}

	if (rpd->session_timeout.expire_tv.tv_sec && !(rpd->termination_action == Termination_Action_RADIUS_Request && rpd->ses->ctrl->ppp)) {
		rpd->ses->session_timeout = rpd->session_timeout.expire_tv.tv_sec;
		rpd->session_timeout.expire_tv.tv_sec = 0;
	}

	if (dns.ses)
		triton_event_fire(EV_DNS, &dns);

	if (wins.ses)
		triton_event_fire(EV_WINS, &wins);

	if (!rpd->ses->ipv6_dp && !list_empty(&rpd->ipv6_dp.prefix_list))
		rpd->ses->ipv6_dp = &rpd->ipv6_dp;

	return res;
}

static int rad_pwdb_check(struct pwdb_t *pwdb, struct ap_session *ses, pwdb_callback cb, void *cb_arg, const char *username, int type, va_list _args)
{
	int r = PWDB_NO_IMPL;
	va_list args;
	int chap_type;
	struct radius_pd_t *rpd = find_pd(ses);
	char username1[256];

	if (!rpd) {
		log_emerg("radius:%s:BUG: rpd not found\n", __func__);
		abort();
	}

	if (conf_strip_realm || conf_default_realm) {
		int len = strchrnul(username, '@') - username;
		if (conf_strip_realm && username[len]) {
			if (len > sizeof(username1) - 1) {
				log_ppp_error("radius: username is too large to strip realm\n");
				return PWDB_DENIED;
			}
			username = memcpy(username1, username, len);
			username1[len] = '\0';
		}
		if (conf_default_realm && username[len] == '\0') {
			if (len + conf_default_realm_len > sizeof(username1) - 2) {
				log_ppp_error("radius: username is too large to append realm\n");
				return PWDB_DENIED;
			}
			if (username != username1)
				username = memcpy(username1, username, len);
			username1[len++] = '@';
			memcpy(username1 + len, conf_default_realm, conf_default_realm_len);
			username1[len + conf_default_realm_len] = '\0';
		}
	}

	rpd->auth_ctx = mempool_alloc(auth_ctx_pool);
	memset(rpd->auth_ctx, 0, sizeof(*rpd->auth_ctx));

	rpd->auth_ctx->cb = cb;
	rpd->auth_ctx->cb_arg = cb_arg;

	va_copy(args, _args);

	switch(type) {
		case PPP_PAP:
			r = rad_auth_pap(rpd, username, args);
			break;
		case PPP_CHAP:
			chap_type = va_arg(args, int);
			switch(chap_type) {
				case CHAP_MD5:
					r = rad_auth_chap_md5(rpd, username, args);
					break;
				case MSCHAP_V1:
					r = rad_auth_mschap_v1(rpd, username, args);
					break;
				case MSCHAP_V2:
					r = rad_auth_mschap_v2(rpd, username, args);
					break;
			}
			break;
		case 0:
			r = rad_auth_null(rpd, username, args);
			break;
	}

	va_end(args);

	if (r == PWDB_DENIED) {
		if (rpd->auth_ctx->req)
			rad_req_free(rpd->auth_ctx->req);
		mempool_free(rpd->auth_ctx);
		rpd->auth_ctx = NULL;
	}

	return r;
}

static struct ipv4db_item_t *get_ipv4(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);

	if (!rpd)
		return NULL;

	if (rpd->ipv4_addr.peer_addr)
		return &rpd->ipv4_addr;

	return NULL;
}

static struct ipv6db_item_t *get_ipv6(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);

	if (!rpd)
		return NULL;

	rpd->ipv6_addr.intf_id = 0;

	if (!list_empty(&rpd->ipv6_addr.addr_list))
		return &rpd->ipv6_addr;

	return NULL;
}

static struct ipv6db_prefix_t *get_ipv6_prefix(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);

	if (!rpd)
		return NULL;

	if (!list_empty(&rpd->ipv6_dp.prefix_list)) {
		rpd->ipv6_dp_assigned = 1;
		return &rpd->ipv6_dp;
	}

	return NULL;
}

static void session_timeout(struct triton_timer_t *t)
{
	struct radius_pd_t *rpd = container_of(t, typeof(*rpd), session_timeout);

	log_ppp_msg("radius: session timed out\n");

	if (rpd->ses->stop_time)
		return;

	if (rpd->termination_action == Termination_Action_RADIUS_Request && rpd->ses->ctrl->ppp) {
		if (ppp_auth_restart(container_of(rpd->ses, struct ppp_t, ses)))
			ap_session_terminate(rpd->ses, TERM_SESSION_TIMEOUT, 0);
	} else
		ap_session_terminate(rpd->ses, TERM_SESSION_TIMEOUT, 0);
}

void rad_update_session_timeout(struct radius_pd_t *rpd, int timeout)
{
	rpd->session_timeout.expire_tv.tv_sec = timeout;
	rpd->session_timeout.expire = session_timeout;

	if (rpd->session_timeout.tpd)
		triton_timer_mod(&rpd->session_timeout, 0);
	else
		triton_timer_add(rpd->ses->ctrl->ctx, &rpd->session_timeout, 0);
}

static void ses_starting(struct ap_session *ses)
{
	struct radius_pd_t *rpd = mempool_alloc(rpd_pool);

	memset(rpd, 0, sizeof(*rpd));
	rpd->pd.key = &pd_key;
	rpd->ses = ses;
	rpd->refs = 1;
	pthread_mutex_init(&rpd->lock, NULL);
	INIT_LIST_HEAD(&rpd->plugin_list);
	INIT_LIST_HEAD(&rpd->ipv6_addr.addr_list);
	INIT_LIST_HEAD(&rpd->ipv6_dp.prefix_list);

	rpd->ipv4_addr.owner = &ipdb;
	rpd->ipv6_addr.owner = &ipdb;
	rpd->ipv6_dp.owner = &ipdb;

	list_add_tail(&rpd->pd.entry, &ses->pd_list);

	pthread_rwlock_wrlock(&sessions_lock);
	list_add_tail(&rpd->entry, &sessions);
	pthread_rwlock_unlock(&sessions_lock);

#ifdef USE_BACKUP
	if (ses->state == AP_STATE_RESTORE && ses->backup)
		radius_restore_session(ses, rpd);
#endif
}

static void ses_acct_start(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);

	if (!conf_accounting)
		return;

	if (!rpd || !rpd->authenticated)
		return;

	if (rad_acct_start(rpd)) {
		ap_session_terminate(rpd->ses, TERM_NAS_ERROR, 0);
		return;
	}

	ses->acct_start++;
}

static void ses_started(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);
	struct framed_ip6_route *fr6;
	struct framed_route *fr;

	if (!rpd) {
		log_emerg("radius:%s:BUG: rpd not found\n", __func__);
		abort();
	}

	if (rpd->session_timeout.expire_tv.tv_sec) {
		rpd->session_timeout.expire = session_timeout;
		triton_timer_add(ses->ctrl->ctx, &rpd->session_timeout, 0);
	}

	for (fr6 = rpd->fr6; fr6; fr6 = fr6->next) {
		bool gw_spec = !IN6_IS_ADDR_UNSPECIFIED(&fr6->gw);
		char nbuf[INET6_ADDRSTRLEN];
		char gwbuf[INET6_ADDRSTRLEN];

		if (ip6route_add(gw_spec ? 0 : rpd->ses->ifindex, &fr6->prefix, fr6->plen, gw_spec ? &fr6->gw : NULL, 3, fr6->prio)) {
			log_ppp_warn("radius: failed to add route %s/%hhu %s %u\n",
				     u_ip6str(&fr6->prefix, nbuf), fr6->plen,
				     u_ip6str(&fr6->gw, gwbuf), fr6->prio);
		}
	}

	for (fr = rpd->fr; fr; fr = fr->next) {
		if (iproute_add(fr->gw ? 0 : rpd->ses->ifindex, 0, fr->dst, fr->gw, 3, fr->mask, fr->prio)) {
			char dst[17], gw[17];
			u_inet_ntoa(fr->dst, dst);
			u_inet_ntoa(fr->gw, gw);
			log_ppp_warn("radius: failed to add route %s/%i %s %u\n", dst, fr->mask, gw, fr->prio);
		}
	}

	if (rpd->auth_reply) {
		rad_packet_free(rpd->auth_reply);
		rpd->auth_reply = NULL;
	}
}

static void ses_finishing(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);
	struct framed_ip6_route *fr6;
	struct framed_route *fr;

	if (!rpd) {
		log_emerg("radius:%s:BUG: rpd not found\n", __func__);
		abort();
	}

	if (rpd->auth_ctx) {
		rad_server_req_cancel(rpd->auth_ctx->req, 1);
		rad_req_free(rpd->auth_ctx->req);
		mempool_free(rpd->auth_ctx);
		rpd->auth_ctx = NULL;
	}

	for (fr6 = rpd->fr6; fr6; fr6 = fr6->next) {
		/* Routes that have an unspecified gateway have been defined
		 * using the session's virtual network interface. No need to
		 * delete those routes here: kernel automatically drops them
		 * when the interface is removed.
		 */
		if (!IN6_IS_ADDR_UNSPECIFIED(&fr6->gw))
			ip6route_del(0, &fr6->prefix, fr6->plen, &fr6->gw, 3, fr6->prio);
	}

	for (fr = rpd->fr; fr; fr = fr->next) {
		if (fr->gw)
			iproute_del(0, 0, fr->dst, fr->gw, 3, fr->mask, fr->prio);
	}

	if (rpd->acct_started || rpd->acct_req)
	    rad_acct_stop(rpd);

	if (rpd->acct_interim_timer.tpd)
		triton_timer_del(&rpd->acct_interim_timer);
}

static void ses_finished(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);
	struct ipv6db_addr_t *a;
	struct framed_ip6_route *fr6;

	if (!rpd) {
		log_emerg("radius:%s:BUG: rpd not found\n", __func__);
		abort();
	}

	struct framed_route *fr = rpd->fr;

	pthread_rwlock_wrlock(&sessions_lock);
	pthread_mutex_lock(&rpd->lock);
	list_del(&rpd->entry);
	pthread_mutex_unlock(&rpd->lock);
	pthread_rwlock_unlock(&sessions_lock);

	if (rpd->auth_ctx) {
		rad_server_req_cancel(rpd->auth_ctx->req, 1);
		rad_req_free(rpd->auth_ctx->req);
		mempool_free(rpd->auth_ctx);
		rpd->auth_ctx = NULL;
	}

	if (rpd->acct_req) {
		if (rpd->acct_started)
			rad_acct_stop_defer(rpd);
		else {
			rad_server_req_cancel(rpd->acct_req, 1);
			rad_req_free(rpd->acct_req);
		}
	}

	if (rpd->acct_username)
		_free(rpd->acct_username);

	if (rpd->auth_reply)
		rad_packet_free(rpd->auth_reply);

	if (rpd->dm_coa_req)
		dm_coa_cancel(rpd);

	if (rpd->session_timeout.tpd)
		triton_timer_del(&rpd->session_timeout);

	if (rpd->attr_class)
		_free(rpd->attr_class);

	if (rpd->attr_state)
		_free(rpd->attr_state);

	while (!list_empty(&rpd->ipv6_addr.addr_list)) {
		a = list_entry(rpd->ipv6_addr.addr_list.next, typeof(*a), entry);
		list_del(&a->entry);
		_free(a);
	}

	while (!list_empty(&rpd->ipv6_dp.prefix_list)) {
		a = list_entry(rpd->ipv6_dp.prefix_list.next, typeof(*a), entry);
		list_del(&a->entry);
		_free(a);
	}

	fr6 = rpd->fr6;
	while (fr6) {
		struct framed_ip6_route *next = fr6->next;

		_free(fr6);
		fr6 = next;
	}

	while (fr) {
		struct framed_route *next = fr->next;
		_free(fr);
		fr = next;
	}

	list_del(&rpd->pd.entry);

	release_pd(rpd);
}

static void force_interim_update(struct ap_session *ses)
{
	struct radius_pd_t *rpd = find_pd(ses);

	if (ses->terminating)
		return;

	if (!rpd)
		return;

	rad_acct_force_interim_update(rpd);
}

struct radius_pd_t *find_pd(struct ap_session *ses)
{
	struct ap_private *pd;
	struct radius_pd_t *rpd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key) {
			rpd = container_of(pd, typeof(*rpd), pd);
			return rpd;
		}
	}

	return NULL;
}

void hold_pd(struct radius_pd_t *rpd)
{
	rpd->refs++;
}

void release_pd(struct radius_pd_t *rpd)
{
	if (--rpd->refs == 0)
		mempool_free(rpd);
}

struct radius_pd_t *rad_find_session(const char *sessionid, const char *username, const char *port_id, int port, in_addr_t ipaddr, const char *csid)
{
	struct radius_pd_t *rpd;

	pthread_rwlock_rdlock(&sessions_lock);
	list_for_each_entry(rpd, &sessions, entry) {
		if (!rpd->ses->username)
			continue;
		if (sessionid && strcmp(sessionid, rpd->ses->sessionid))
			continue;
		if (username && strcmp(username, rpd->ses->username))
			continue;
		if (port >= 0 && port != rpd->ses->unit_idx)
			continue;
		if (port_id && strcmp(port_id, rpd->ses->ifname))
			continue;
		if (ipaddr && rpd->ses->ipv4 && ipaddr != rpd->ses->ipv4->peer_addr)
			continue;
		if (csid && rpd->ses->ctrl->calling_station_id && strcmp(csid, rpd->ses->ctrl->calling_station_id))
			continue;
		pthread_mutex_lock(&rpd->lock);
		pthread_rwlock_unlock(&sessions_lock);
		return rpd;
	}
	pthread_rwlock_unlock(&sessions_lock);
	return NULL;
}

struct radius_pd_t *rad_find_session_pack(struct rad_packet_t *pack)
{
	struct rad_attr_t *attr;
	const char *sessionid = NULL;
	const char *username = NULL;
	const char *csid = NULL;
	int port = -1;
	const char *port_id = NULL;
	in_addr_t ipaddr = 0;

	list_for_each_entry(attr, &pack->attrs, entry) {
		if (attr->vendor)
			continue;
		switch(attr->attr->id) {
			case Acct_Session_Id:
				sessionid = attr->val.string;
				break;
			case User_Name:
				username = attr->val.string;
				break;
			case NAS_Port:
				port = attr->val.integer;
				break;
			case NAS_Port_Id:
				port_id = attr->val.string;
				break;
			case Framed_IP_Address:
				if (attr->val.ipaddr != htonl(0xfffffffe))
					ipaddr = attr->val.ipaddr;
				break;
			case Calling_Station_Id:
				csid = attr->val.string;
				break;
		}
	}

	if (!sessionid && !username && !port_id && port == -1 && ipaddr == 0 && !csid)
		return NULL;

	return rad_find_session(sessionid, username, port_id, port, ipaddr, csid);
}

int rad_check_nas_pack(struct rad_packet_t *pack)
{
	struct rad_attr_t *attr;
	const char *ident = NULL;
	in_addr_t ipaddr = 0;

	list_for_each_entry(attr, &pack->attrs, entry) {
		if (!strcmp(attr->attr->name, "NAS-Identifier"))
			ident = attr->val.string;
		else if (!strcmp(attr->attr->name, "NAS-IP-Address"))
			ipaddr = attr->val.ipaddr;
	}

	if (conf_require_nas_ident && !ident && !ipaddr)
		return -1;

	if (conf_nas_identifier && ident && strcmp(conf_nas_identifier, ident))
		return -1;

	if (conf_nas_ip_address && ipaddr && conf_nas_ip_address != ipaddr)
		return -1;

	return 0;
}

void __export rad_register_plugin(struct ap_session *ses, struct rad_plugin_t *plugin)
{
	struct radius_pd_t *rpd = find_pd(ses);

	if (!rpd)
		return;

	list_add_tail(&plugin->entry, &rpd->plugin_list);
}

static struct ipdb_t ipdb = {
	.get_ipv4 = get_ipv4,
	.get_ipv6 = get_ipv6,
	.get_ipv6_prefix = get_ipv6_prefix,
};

static struct pwdb_t pwdb = {
	.check = rad_pwdb_check,
};

static int parse_server(const char *opt, in_addr_t *addr, int *port, char **secret, char *bind_device, unsigned int *bind_default)
{
	char *str = _strdup(opt);
	char *p1, *p2, *p3;

	p1 = strstr(str, ":");
	p2 = strstr(str, ",");

	if (p1)
		*p1 = 0;
	if (p2)
		*p2 = 0;
	else {
		_free(str);
		return -1;
	}

	p3 = strstr(p2 + 1, ",bind-device=");
	if (p3)
	{
		*p3 = 0;
		if ( strlen(p3 + 13) > IFNAMSIZ - 1 )
		{
			_free(str);
			return -1;
		}
		strcpy ( bind_device, p3 + 13);
		*bind_default = 0;
	} else
		*bind_default = 1;

	*addr = inet_addr(str);

	if (p1) {
		*port = atoi(p1 + 1);
		if (*port <=0) {
			_free(str);
			return -1;
		}
	}

	p1 = _strdup(p2 + 1);
	p2 = *secret;
	*secret = p1;
	if (p2)
		_free(p2);

	_free(str);

	return 0;
}

static int load_config(void)
{
	char *opt;

	opt = conf_get_opt("radius", "max-try");
	if (opt && atoi(opt) > 0)
		conf_max_try = atoi(opt);

	opt = conf_get_opt("radius", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("radius", "acct-timeout");
	if (opt && atoi(opt) >= 0)
		conf_acct_timeout = atoi(opt);

	opt = conf_get_opt("radius", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	opt = conf_get_opt("radius", "interim-verbose");
	if (opt && atoi(opt) >= 0)
		conf_interim_verbose = atoi(opt) > 0;

	opt = conf_get_opt("radius", "nas-ip-address");
	if (opt)
		conf_nas_ip_address = inet_addr(opt);

	if (conf_nas_identifier)
		_free(conf_nas_identifier);
	opt = conf_get_opt("radius", "nas-identifier");
	if (opt)
		conf_nas_identifier = _strdup(opt);
	else
		conf_nas_identifier = NULL;

	opt = conf_get_opt("radius", "gw-ip-address");
	if (opt)
		conf_gw_ip_address = inet_addr(opt);

	opt = conf_get_opt("radius", "bind");
	if (opt)
		conf_bind = inet_addr(opt);
	else if (conf_nas_ip_address)
		conf_bind = conf_nas_ip_address;

	opt = conf_get_opt("radius", "dae-server");
	if (opt && parse_server(opt, &conf_dm_coa_server, &conf_dm_coa_port, &conf_dm_coa_secret, conf_dm_coa_bind_device, &conf_dm_coa_bind_default)) {
		log_emerg("radius: failed to parse dae-server\n");
		return -1;
	}

	{
		int entries = 0;
		int dae_allowed_present = 0;
		int parse_rc = 0;

		pthread_rwlock_wrlock(&dae_allow_lock);
		dae_allow_clear();
		opt = conf_get_opt("radius", "dae-allowed");
		if (opt) {
			dae_allowed_present = 1;
			dae_allow_ranges = _malloc(sizeof(*dae_allow_ranges));
			if (!dae_allow_ranges) {
				log_emerg("radius: failed to allocate dae-allowed list\n");
				parse_rc = -1;
				goto dae_allow_unlock;
			}
			INIT_LIST_HEAD(dae_allow_ranges);
			if (dae_allow_parse(opt, &entries)) {
				log_emerg("radius: failed to parse dae-allowed\n");
				dae_allow_clear();
				parse_rc = -1;
				goto dae_allow_unlock;
			}
		}

		if (dae_allowed_present && entries == 0) {
			log_warn("radius: dae-allowed has no valid entries, DAE source restrictions are disabled\n");
			dae_allow_clear();
		}

dae_allow_unlock:
		pthread_rwlock_unlock(&dae_allow_lock);
		if (parse_rc)
			return -1;
	}

	opt = conf_get_opt("radius", "sid-in-auth");
	if (opt)
		conf_sid_in_auth = atoi(opt);

	opt = conf_get_opt("radius", "require-nas-identification");
	if (opt)
		conf_require_nas_ident = atoi(opt);

	opt = conf_get_opt("radius", "acct-interim-interval");
	if (opt && atoi(opt) >= 0)
		conf_acct_interim_interval = atoi(opt);

	opt = conf_get_opt("radius", "acct-interim-jitter");
	if (opt && atoi(opt) >= 0)
		conf_acct_interim_jitter = atoi(opt);

	opt = conf_get_opt("radius", "acct-delay-time");
	if (opt)
		conf_acct_delay_time = atoi(opt);

	conf_attr_tunnel_type = conf_get_opt("radius", "attr-tunnel-type");

	conf_default_realm = conf_get_opt("radius", "default-realm");
	if (conf_default_realm)
		conf_default_realm_len = strlen(conf_default_realm);

	opt = conf_get_opt("radius", "strip-realm");
	if (opt && atoi(opt) >= 0)
		conf_strip_realm = atoi(opt) > 0;

	opt = conf_get_opt("radius", "nas-port-id-in-req");
	if (opt)
		conf_nas_port_id_in_req = atoi(opt);

	opt = conf_get_opt("radius", "acct-delay-start");
	if (opt)
		conf_acct_delay_start = atoi(opt);
	else
		conf_acct_delay_start = 0;

	opt = conf_get_opt("radius", "blast-protection");
	if (opt && atoi(opt) > 0) {
		conf_blast_protection = 1;
	} else {
		conf_blast_protection = 0;
	}
	opt = conf_get_opt("radius", "framed-route-strict");
	if (opt && atoi(opt) > 0)
		conf_framed_route_strict = 1;
	else
		conf_framed_route_strict = 0;

	return 0;
}

static void radius_init(void)
{
	const char *dict = NULL;
	struct conf_sect_t *s = conf_get_section("radius");

	if (!s) {
		log_emerg("radius: config section not found\n");
		_exit(EXIT_FAILURE);
	}

	struct conf_option_t *opt1;

	rpd_pool = mempool_create(sizeof(struct radius_pd_t));
	auth_ctx_pool = mempool_create(sizeof(struct radius_auth_ctx));

	if (load_config()) {
		log_emerg("radius: config load failed\n");
		_exit(EXIT_FAILURE);
	}

	list_for_each_entry(opt1, &s->items, entry) {
		if (strcmp(opt1->name, "dictionary") || !opt1->val)
			continue;
		dict = opt1->val;
		if (rad_dict_load(dict)) {
			log_emerg("radius: dictionary load failed\n");
			_exit(0);
		}
	}

	if (!dict && rad_dict_load(DICTIONARY)) {
		log_emerg("radius: default dictionary load failed\n");
		_exit(0);
	}

	pwdb_register(&pwdb);
	ipdb_register(&ipdb);

	triton_event_register_handler(EV_SES_STARTING, (triton_event_func)ses_starting);
	triton_event_register_handler(EV_SES_POST_STARTED, (triton_event_func)ses_started);
	triton_event_register_handler(EV_SES_ACCT_START, (triton_event_func)ses_acct_start);
	triton_event_register_handler(EV_SES_FINISHING, (triton_event_func)ses_finishing);
	triton_event_register_handler(EV_SES_FINISHED, (triton_event_func)ses_finished);
	triton_event_register_handler(EV_FORCE_INTERIM_UPDATE, (triton_event_func)force_interim_update);
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(51, radius_init);
