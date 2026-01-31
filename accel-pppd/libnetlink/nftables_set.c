#include "config.h" 

#ifdef HAVE_NFTABLES

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <pthread.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

#include "triton.h"
#include "log.h"

#include "libnetlink.h" 
#include "nftables_set.h"

#include "memdebug.h"

struct nlmsghdr *__build_nlmsghdr(uint8_t *buf, uint16_t type, uint8_t family, uint16_t flags, uint32_t seq, uint16_t res_id)
{
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfh;
    uint8_t *ptr;
    size_t len;

    len = NLA_ALIGN(sizeof(struct nlmsghdr));
    nlh = (struct nlmsghdr *)buf; 
    memset(buf, 0, len);

    nlh->nlmsg_len = len; 
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = seq; 

    ptr = (uint8_t *)nlh + nlh->nlmsg_len;
    len = NLA_ALIGN(sizeof(struct nfgenmsg));
    nlh->nlmsg_len += len;
    memset(ptr, 0, len);
    nfh = (struct nfgenmsg *)ptr;	
    nfh->nfgen_family = family;
    nfh->version = NFNETLINK_V0;
    nfh->res_id = htons(res_id); 

    return nlh;
}

int __nftables_set_cmd(struct nftables_set_key *key, uint32_t addr, uint16_t type, uint16_t flags) 
{    
    struct rtnl_handle rth;
    struct nlmsghdr *hdr;
    struct nlattr *nest1, *nest2, *nest3;

    uint8_t buf[4096];
    uint8_t *bufptr = buf;

    int buflen = 0;
    int seq = time(NULL);

    if (rtnl_open_byproto(&rth, 0, NETLINK_NETFILTER)) {
        log_error("nftables_set: cannot open rtnetlink\n");
        return -1;
    }
 
    hdr = __build_nlmsghdr(bufptr, 
        NFNL_MSG_BATCH_BEGIN, 
        AF_UNSPEC,
        0, seq++, NFNL_SUBSYS_NFTABLES);

    buflen += hdr->nlmsg_len;   
    bufptr += hdr->nlmsg_len;

    hdr = __build_nlmsghdr(bufptr, 
        (NFNL_SUBSYS_NFTABLES << 8) | type,
        key->family,
        flags,
        seq++, 0);  
 
    nlattr_put(hdr, NFTA_SET_ELEM_LIST_SET, strlen(key->set)+1, key->set); 
    nlattr_put(hdr, NFTA_SET_ELEM_LIST_TABLE, strlen(key->table)+1, key->table);
    nest1 = nlattr_nest_start(hdr, NFTA_SET_ELEM_LIST_ELEMENTS);
    nest2 = nlattr_nest_start(hdr, 1);  
    nest3 = nlattr_nest_start(hdr, NFTA_SET_ELEM_KEY); 
    nlattr_put(hdr, NFTA_DATA_VALUE, sizeof(uint32_t), &addr);
    nlattr_nest_end(hdr, nest3);
    nlattr_nest_end(hdr, nest2);
    nlattr_nest_end(hdr, nest1);

    buflen += hdr->nlmsg_len;	 
    bufptr += hdr->nlmsg_len;

    hdr = __build_nlmsghdr(bufptr, 
        NFNL_MSG_BATCH_END, 
        AF_UNSPEC,
        0, seq++, NFNL_SUBSYS_NFTABLES);

    buflen += hdr->nlmsg_len;   

    if (rtnl_send_check(&rth, (const char *)buf, buflen) < 0)
        goto out_err;

    rtnl_close(&rth);

    return 0;

out_err:
    rtnl_close(&rth);

    return -1; 
}
 
int __export nftables_set_add(struct nftables_set_key *key, uint32_t addr)
{ 
    return __nftables_set_cmd(key, addr, NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
}
 
int __export nftables_set_del(struct nftables_set_key *key, uint32_t addr)
{  
    return __nftables_set_cmd(key, addr, NFT_MSG_DELSETELEM, NLM_F_ACK);
}

int __export nftables_set_flush(struct nftables_set_key *key)
{ 
    struct rtnl_handle rth;
    struct nlmsghdr *hdr; 

    uint8_t buf[4096];
    uint8_t *bufptr = buf;

    int buflen = 0;
    int seq = time(NULL);

    if (rtnl_open_byproto(&rth, 0, NETLINK_NETFILTER)) {
        log_error("nftables_set: cannot open rtnetlink\n");
        return -1;
    }
 
    hdr = __build_nlmsghdr(bufptr, 
        NFNL_MSG_BATCH_BEGIN, 
        AF_UNSPEC,
        0, seq++, NFNL_SUBSYS_NFTABLES);

    buflen += hdr->nlmsg_len;   
    bufptr += hdr->nlmsg_len;

    hdr = __build_nlmsghdr(bufptr, 
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM,
        key->family,
        NLM_F_ACK, seq++, 0);

    nlattr_put(hdr, NFTA_SET_ELEM_LIST_SET, strlen(key->set)+1, key->set); 
    nlattr_put(hdr, NFTA_SET_ELEM_LIST_TABLE, strlen(key->table)+1, key->table);  

    buflen += hdr->nlmsg_len;	 
    bufptr += hdr->nlmsg_len;

    hdr = __build_nlmsghdr(bufptr, 
        NFNL_MSG_BATCH_END, 
        AF_UNSPEC,
        0, seq++, NFNL_SUBSYS_NFTABLES);

    buflen += hdr->nlmsg_len; 

    if (rtnl_send_check(&rth, (const char *)buf, buflen) < 0)
        goto out_err;

    rtnl_close(&rth);

    return 0;

out_err:
    rtnl_close(&rth);

    return -1; 
}

int __export parse_nftables_set_key_conf(const char *config, struct nftables_set_key *key) {
    if (!config) {
        return 0;
    }

    struct nftables_set_key option = {.family = NFPROTO_UNSPEC, .table="", .set=""}; 

    char *cfg = _strdup(config);
    char *save1, *save2;

    char *pair = strtok_r(cfg, ",", &save1);

    while (pair) {
        char *key = strtok_r(pair, "=", &save2);
        char *value = strtok_r(NULL, "=", &save2);
        if (key && value) {
            if (strcmp(key, "family") == 0) {
                if (strcmp(value, "inet") == 0) {
                    option.family = NFPROTO_INET;
                } else if (strcmp(value, "ip") == 0) {
                    option.family = NFPROTO_IPV4;
                } else {
                    log_error("l4-redirect-nftables: family=%s, but key value must be one of 'ip', 'inet'\n", value);
                    goto error;
                }
            } else if (strcmp(key, "table") == 0) {
                snprintf(option.table, sizeof(option.table), "%s", value);
            } else if (strcmp(key, "set") == 0) {
                snprintf(option.set, sizeof(option.set), "%s", value);
            }
        }
        pair = strtok_r(NULL, ",", &save1);
    }

    if (option.family == NFPROTO_UNSPEC) {
        log_error("l4-redirect-nftables: parsing failed, family=<ip|inet> key value missing\n");
        goto error;
    }

    if (option.table[0] == '\0') {
        log_error("l4-redirect-nftables: parsing failed, table=<name> key value missing\n");
        goto error;
    }

    if (option.set[0] == '\0') {
        log_error("l4-redirect-nftables: parsing failed, set=<name> key value missing\n");
        goto error;
    }

    _free(cfg);
    *key = option;  
    return 1;

error:  
    _free(cfg);
    return 0;
}

#else 

#include <netinet/in.h>
#include "triton.h"
#include "nftables_set.h" 
#include "log.h"

int __export nftables_set_add(struct nftables_set_key *key, uint32_t addr)
{
    return -1;
}

int __export nftables_set_del(struct nftables_set_key *key, uint32_t addr)
{
    return -1;
}

int __export nftables_set_flush(struct nftables_set_key *key)
{
    return -1;
}

int __export parse_nftables_set_key_conf(const char *config, struct nftables_set_key *key) 
{ 
    if (!config) {
        return 0;
    }
    
    log_warn("l4-redirect-nftables: nftables support was not compiled in\n");
    return 0;
}


#endif
