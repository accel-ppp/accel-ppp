#ifndef __NFTABLES_SET_H
#define __NFTABLES_SET_H

#include <netinet/in.h>

struct nftables_set_key {
    uint8_t family;
    char table[64];
    char set[64];
};
 
int nftables_set_add(struct nftables_set_key *key, in_addr_t addr);
int nftables_set_del(struct nftables_set_key *key, in_addr_t addr);
int nftables_set_flush(struct nftables_set_key *key);
int parse_nftables_set_key_conf(const char *conf, struct nftables_set_key *key);

#endif

