#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <arpa/inet.h>

/*
 * Suppress OpenSSL 3.0 deprecation warnings for HMAC API.
 * See crypto.h for detailed explanation.
 */
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "log.h"
#include "mempool.h"
#include "radius_p.h"
#include "attr_defs.h"

#include "memdebug.h"

#define HMAC_MD5_LEN 16
/* Radius header + attribute: type + length */
#define PACKET_SIGNED_OFFSET (20 + 2)

static mempool_t packet_pool;
static mempool_t attr_pool;
static mempool_t buf_pool;

struct rad_packet_t *rad_packet_alloc(int code)
{
	struct rad_packet_t *pack;

	pack = mempool_alloc(packet_pool);
	if (!pack) {
		log_emerg("radius:packet: out of memory\n");
		return NULL;
	}

	memset(pack, 0, sizeof(*pack));
	pack->code = code;
	pack->len = 20;
	pack->id = 1;
	INIT_LIST_HEAD(&pack->attrs);

	return pack;
}

void print_buf(uint8_t *buf,int size)
{
	int i;
	for(i=0;i<size;i++)
		printf("%x ",buf[i]);
	printf("\n");
}


int hmac_md5(const uint8_t *key,  size_t key_len,
             const uint8_t *data, size_t data_len,
             uint8_t out[HMAC_MD5_LEN])
{
    unsigned int len = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx)
        return -1;

    if (HMAC_Init_ex(ctx, key, (int)key_len, EVP_md5(), NULL) != 1)
        goto err;

    if (HMAC_Update(ctx, data, data_len) != 1)
        goto err;

    if (HMAC_Final(ctx, out, &len) != 1 || len != HMAC_MD5_LEN)
        goto err;

    HMAC_CTX_free(ctx);
    return 0;

err:
    HMAC_CTX_free(ctx);
    return -1;
}


int rad_packet_build(struct rad_packet_t *pack, uint8_t *RA)
{
	struct rad_attr_t *attr;
	uint8_t *ptr;

	if (!pack->buf) {
		//ptr = mmap(NULL, REQ_LENGTH_MAX, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		ptr = mempool_alloc(buf_pool);

		//if (ptr == MAP_FAILED) {
		if (!ptr) {
			log_emerg("radius:packet: out of memory\n");
			return -1;
		}

		pack->buf = ptr;
	} else
		ptr = pack->buf;

	*ptr = pack->code; ptr++;
	*ptr = pack->id; ptr++;
	*(uint16_t*)ptr = htons(pack->len); ptr+= 2;
	memcpy(ptr, RA, 16);	ptr+=16;

	list_for_each_entry(attr, &pack->attrs, entry) {
		if (attr->vendor) {
			*ptr = 26; ptr++;
			*ptr = attr->len + 2 + 6; ptr++;
			*(uint32_t *)ptr = htonl(attr->vendor->id); ptr+=4;
		}
		*ptr = attr->attr->id; ptr++;
		*ptr = attr->len + 2; ptr++;
		switch(attr->attr->type) {
			case ATTR_TYPE_INTEGER:
				*(uint32_t*)ptr = htonl(attr->val.integer);
				break;
			case ATTR_TYPE_OCTETS:
			case ATTR_TYPE_STRING:
				memcpy(ptr, attr->val.string, attr->len);
				break;
			case ATTR_TYPE_IPADDR:
			case ATTR_TYPE_IFID:
			case ATTR_TYPE_IPV6ADDR:
				memcpy(ptr, &attr->val, attr->len);
				break;
			case ATTR_TYPE_DATE:
				*(uint32_t*)ptr = htonl(attr->val.date);
				break;
			case ATTR_TYPE_IPV6PREFIX:
				ptr[0] = 0;
				ptr[1] = attr->val.ipv6prefix.len;
				memcpy(ptr + 2, &attr->val.ipv6prefix.prefix, sizeof(attr->val.ipv6prefix.prefix));
				break;
			default:
				log_emerg("radius:packet:BUG: unknown attribute type\n");
				abort();
		}
		ptr += attr->len;
	}

	//print_buf(pack->buf, pack->len);
	return 0;
}

int rad_packet_recv(int fd, struct rad_packet_t **p, struct sockaddr_in *addr)
{
	struct rad_packet_t *pack;
	struct rad_attr_t *attr;
	struct rad_dict_attr_t *da;
	struct rad_dict_vendor_t *vendor;
	uint8_t *ptr;
	int n, id, len, vendor_id;
	socklen_t addr_len = sizeof(*addr);

	*p = NULL;

	pack = rad_packet_alloc(0);
	if (!pack)
		return 0;

	ptr = mempool_alloc(buf_pool);
	if (!ptr) {
		log_emerg("radius:packet: out of memory\n");
		goto out_err;
	}

	pack->buf = ptr;
	clock_gettime(CLOCK_MONOTONIC, &pack->tv);

	while (1) {
		if (addr)
			n = recvfrom(fd, pack->buf, REQ_LENGTH_MAX, 0, (struct sockaddr *)addr, &addr_len);
		else
			n = read(fd, pack->buf, REQ_LENGTH_MAX);
		if (n < 0) {
			rad_packet_free(pack);
			if (errno == EAGAIN)
				return 1;

			if (errno != ECONNREFUSED)
				log_ppp_error("radius:packet:read: %s\n", strerror(errno));

			return -1;
		}
		break;
	}

	if (n < 20) {
		log_ppp_warn("radius:packet: short packed received (%i)\n", n);
		goto out_err;
	}

	pack->code = *ptr; ptr++;
	pack->id = *ptr; ptr++;
	pack->len = ntohs(*(uint16_t*)ptr); ptr += 2;

	if (pack->len > n) {
		log_ppp_warn("radius:packet: short packet received %i, expected %i\n", pack->len, n);
		goto out_err;
	}

	ptr += 16;
	n -= 20;

	while (n>0) {
		id = *ptr; ptr++;
		len = *ptr - 2; ptr++;
		if (len < 0) {
			log_ppp_warn("radius:packet short attribute len received\n");
			goto out_err;
		}
		if (2 + len > n) {
			log_ppp_warn("radius:packet: too long attribute received (%i, %i)\n", id, len);
			goto out_err;
		}
		if (id == 26) {
			if (len < 4) {
				log_ppp_warn("radius:packet: vendor attribute too short (%i)\n", len);
				goto out_err;
			}
			vendor_id = ntohl(*(uint32_t *)ptr);
			vendor = rad_dict_find_vendor_id(vendor_id);
			if (vendor) {
				if (len < 4 + vendor->tag + vendor->len) {
					log_ppp_warn("radius:packet: vendor %i attribute too short (%i)\n", vendor_id, len);
					goto out_err;
				}
				ptr += 4;

				if (vendor->tag == 2)
					id = (uint16_t)ntohs(*(uint16_t *)ptr);
				else
					id = *ptr;

				ptr += vendor->tag;

				if (vendor->len == 2)
					len = (uint16_t)ntohs(*(uint16_t *)ptr);
				else
					len = *ptr;

				ptr += vendor->len;

				len -= vendor->tag + vendor->len;

				n -= 4 + vendor->tag + vendor->len;
				if (len < 0) {
					log_ppp_warn("radius:packet invalid vendor attribute len received\n");
					goto out_err;
				}
				if (2 + len > n) {
					log_ppp_warn("radius:packet: too long vendor attribute received (%i, %i)\n", id, len);
					goto out_err;
				}
			} else
				log_ppp_warn("radius:packet: vendor %i not found\n", id);
		} else
			vendor = NULL;
		da = rad_dict_find_attr_id(vendor, id);
		if (da) {
			attr = mempool_alloc(attr_pool);
			if (!attr) {
				log_emerg("radius:packet: out of memory\n");
				goto out_err;
			}
			memset(attr, 0, sizeof(*attr));
			attr->vendor = vendor;
			attr->attr = da;
			attr->len = len;
			attr->raw = ptr;

			if (!da->array) {
				switch (da->type) {
					case ATTR_TYPE_STRING:
						attr->alloc = 1;
						attr->val.string = _malloc(len + 1);
						memcpy(attr->val.string, ptr, len);
						attr->val.string[len] = 0;
						break;
					case ATTR_TYPE_OCTETS:
					case ATTR_TYPE_ETHER:
					case ATTR_TYPE_TLV:
						attr->val.octets = ptr;
						break;
					case ATTR_TYPE_INTEGER:
						if (len != da->size) {
							log_ppp_warn("radius:packet: attribute %s has invalid length %i (must be %i)\n", da->name, len, da->size);
							break;
						}
						if (len == 4)
							attr->val.integer = ntohl(*(uint32_t*)ptr);
						else if (len == 2)
							attr->val.integer = ntohs(*(uint16_t*)ptr);
						else if (len == 1)
							attr->val.integer = *ptr;
						break;
					case ATTR_TYPE_DATE:
						if (len == 4)
							attr->val.integer = ntohl(*(uint32_t*)ptr);
						else
							log_ppp_warn("radius:packet: attribute %s has invalid length %i (must be 4)\n", da->name, len);
						break;
					case ATTR_TYPE_IPADDR:
					case ATTR_TYPE_IFID:
					case ATTR_TYPE_IPV6ADDR:
						if (len == da->size)
							memcpy(&attr->val.integer, ptr, len);
						else
							log_ppp_warn("radius:packet: attribute %s has invalid length %i (must be %i)\n", da->name, len, da->size);
						break;
					case ATTR_TYPE_IPV6PREFIX:
						if (len < 2 || len > 18) { /* RFC 8044 §3.10 ipv6prefix */
							log_ppp_warn("radius:packet: attribute %s has invalid length %i (must be from 2 to 18)\n", da->name, len);
							break;
						}
						if (ptr[1] > 128) {
							log_ppp_warn("radius:packet: attribute %s has invalid prefix length %u (must be from 0 to 128)\n", da->name, ptr[1]);
							break;
						}
						attr->val.ipv6prefix.len = ptr[1];
						memset(&attr->val.ipv6prefix.prefix, 0, sizeof(attr->val.ipv6prefix.prefix));
						memcpy(&attr->val.ipv6prefix.prefix, ptr + 2, len - 2);
						break;
				}
			}
			list_add_tail(&attr->entry, &pack->attrs);
		} else
			log_ppp_warn("radius:packet: unknown attribute received (%i,%i)\n", vendor ? vendor->id : 0, id);
		ptr += len;
		n -= 2 + len;
	}

	*p = pack;

	return 0;

out_err:
	rad_packet_free(pack);
	return 1;
}

void rad_packet_free(struct rad_packet_t *pack)
{
	struct rad_attr_t *attr;

	if (pack->buf)
		mempool_free(pack->buf);
		//munmap(pack->buf, REQ_LENGTH_MAX);

	if (pack->secret)
	  _free(pack->secret);

	while(!list_empty(&pack->attrs)) {
		attr = list_entry(pack->attrs.next, typeof(*attr), entry);
		list_del(&attr->entry);
		if (attr->alloc)
			_free(attr->val.string);
		mempool_free(attr);
	}

	mempool_free(pack);
}

static void print_octets(uint8_t *raw, int len, void (*print)(const char *fmt, ...))
{
	print(" 0x");
	while (len--)
		print("%02x", *raw++);
}

void rad_packet_print(struct rad_packet_t *pack, struct rad_server_t *s, void (*print)(const char *fmt, ...))
{
	struct rad_attr_t *attr;
	struct rad_dict_value_t *val;
	char ip_str[50];
	union {
		uint64_t ifid;
		uint16_t u16[4];
	} ifid_u;
	in_addr_t addr;

	if (s)
		print("[RADIUS(%i) ", s->id);
	else
		print("[RADIUS ");

	switch(pack->code) {
		case CODE_ACCESS_REQUEST:
			print("Access-Request");
			break;
		case CODE_ACCESS_CHALLENGE:
			print("Access-Challenge");
			break;
		case CODE_ACCESS_ACCEPT:
			print("Access-Accept");
			break;
		case CODE_ACCESS_REJECT:
			print("Access-Reject");
			break;
		case CODE_ACCOUNTING_REQUEST:
			print("Accounting-Request");
			break;
		case CODE_ACCOUNTING_RESPONSE:
			print("Accounting-Response");
			break;
		case CODE_DISCONNECT_REQUEST:
			print("Disconnect-Request");
			break;
		case CODE_DISCONNECT_ACK:
			print("Disconnect-ACK");
			break;
		case CODE_DISCONNECT_NAK:
			print("Disconnect-NAK");
			break;
		case CODE_COA_REQUEST:
			print("CoA-Request");
			break;
		case CODE_COA_ACK:
			print("CoA-ACK");
			break;
		case CODE_COA_NAK:
			print("CoA-NAK");
			break;
		default:
			print("Unknown (%i)", pack->code);
	}

	print(" id=%x", pack->id);

	list_for_each_entry(attr, &pack->attrs, entry) {
		print(" <%s", attr->attr->name);

		if (attr->attr->array)
			print_octets(attr->raw, attr->len, print);
		else {
			switch (attr->attr->type) {
				case ATTR_TYPE_INTEGER:
					val = rad_dict_find_val(attr->attr, attr->val);
					if (val)
						print(" %s", val->name);
					else
						print(" %u", attr->val.integer);
					break;
				case ATTR_TYPE_STRING:
					print(" \"%s\"", attr->val.string);
					break;
				case ATTR_TYPE_IPADDR:
					addr = ntohl(attr->val.ipaddr);
					print(" %i.%i.%i.%i", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
					break;
				case ATTR_TYPE_IFID:
					ifid_u.ifid = attr->val.ifid;
					print(" %x:%x:%x:%x", ntohs(ifid_u.u16[0]), ntohs(ifid_u.u16[1]), ntohs(ifid_u.u16[2]), ntohs(ifid_u.u16[3]));
					break;
				case ATTR_TYPE_IPV6ADDR:
					inet_ntop(AF_INET6, &attr->val.ipv6addr, ip_str, sizeof(ip_str));
					print(" %s", ip_str);
					break;
				case ATTR_TYPE_IPV6PREFIX:
					inet_ntop(AF_INET6, &attr->val.ipv6prefix.prefix, ip_str, sizeof(ip_str));
					print(" %s/%i", ip_str, attr->val.ipv6prefix.len);
					break;
				default:
					print_octets(attr->raw, attr->len, print);
			}
		}

		print(">");
	}

	print("]\n");
}

int __export rad_packet_add_int(struct rad_packet_t *pack, const char *vendor_name, const char *name, int val)
{
	struct rad_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (pack->len + (vendor_name ? 8 : 2) + 4 >= REQ_LENGTH_MAX)
		return -1;

	if (vendor_name) {
		vendor = rad_dict_find_vendor_name(vendor_name);
		if (!vendor)
			return -1;
		attr = rad_dict_find_vendor_attr(vendor, name);
	} else {
		vendor = NULL;
		attr = rad_dict_find_attr(name);
	}

	if (!attr)
		return -1;

	ra = mempool_alloc(attr_pool);
	if (!ra)
		return -1;

	memset(ra, 0, sizeof(*ra));
	ra->vendor = vendor;
	ra->attr = attr;
	ra->len = 4;
	ra->val.integer = val;
	ra->raw = &ra->val;
	list_add_tail(&ra->entry, &pack->attrs);
	pack->len += (vendor_name ? 8 : 2) + 4;

	return 0;
}

int __export rad_packet_change_int(struct rad_packet_t *pack, const char *vendor_name, const char *name, int val)
{
	struct rad_attr_t *ra;

	ra = rad_packet_find_attr(pack, vendor_name, name);
	if (!ra)
		return -1;

	ra->val.integer = val;

	return 0;
}

int __export rad_packet_add_octets(struct rad_packet_t *pack, const char *vendor_name, const char *name, const uint8_t *val, int len)
{
	struct rad_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (pack->len + (vendor_name ? 8 : 2) + len >= REQ_LENGTH_MAX)
		return -1;

	if (vendor_name) {
		vendor = rad_dict_find_vendor_name(vendor_name);
		if (!vendor)
			return -1;
		attr = rad_dict_find_vendor_attr(vendor, name);
	} else {
		vendor = NULL;
		attr = rad_dict_find_attr(name);
	}

	if (!attr)
		return -1;

	ra = mempool_alloc(attr_pool);
	if (!ra) {
		log_emerg("radius: out of memory\n");
		return -1;
	}

	memset(ra, 0, sizeof(*ra));
	ra->vendor = vendor;
	ra->attr = attr;
	ra->len = len;

	if (len) {
		ra->alloc = 1;
		ra->val.octets = _malloc(len);
		if (!ra->val.octets) {
			log_emerg("radius: out of memory\n");
			_free(ra);
			return -1;
		}
		memcpy(ra->val.octets, val, len);
	}

	ra->raw = ra->val.octets;

	list_add_tail(&ra->entry, &pack->attrs);
	pack->len += (vendor_name ? 8 : 2) + len;

	return 0;
}

int __export rad_packet_change_octets(struct rad_packet_t *pack, const char *vendor_name, const char *name, const uint8_t *val, int len)
{
	struct rad_attr_t *ra;

	ra = rad_packet_find_attr(pack, vendor_name, name);
	if (!ra)
		return -1;

	if (ra->len != len) {
		if (pack->len - ra->len + len >= REQ_LENGTH_MAX)
			return -1;

		ra->val.octets = _realloc(ra->val.octets, len);
		if (len && !ra->val.octets) {
			log_emerg("radius: out of memory\n");
			return -1;
		}

		ra->raw = ra->val.octets;

		pack->len += len - ra->len;
		ra->len = len;
	}

	if (len)
		memcpy(ra->val.octets, val, len);

	return 0;
}


int __export rad_packet_add_str(struct rad_packet_t *pack, const char *vendor_name, const char *name, const char *val)
{
	struct rad_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;
	int len = strlen(val);

	if (pack->len + (vendor_name ? 8 : 2) + len >= REQ_LENGTH_MAX)
		return -1;

	if (vendor_name) {
		vendor = rad_dict_find_vendor_name(vendor_name);
		if (!vendor)
			return -1;
		attr = rad_dict_find_vendor_attr(vendor, name);
	} else {
		vendor = NULL;
		attr = rad_dict_find_attr(name);
	}

	if (!attr)
		return -1;

	ra = mempool_alloc(attr_pool);
	if (!ra) {
		log_emerg("radius: out of memory\n");
		return -1;
	}

	memset(ra, 0, sizeof(*ra));
	ra->vendor = vendor;
	ra->attr = attr;
	ra->len = len;
	ra->alloc = 1;
	ra->val.string = _malloc(len + 1);
	if (!ra->val.string) {
		log_emerg("radius: out of memory\n");
		_free(ra);
		return -1;
	}
	memcpy(ra->val.string, val, len);
	ra->val.string[len] = 0;
	ra->raw = ra->val.string;
	list_add_tail(&ra->entry, &pack->attrs);
	pack->len += (vendor_name ? 8 : 2) + len;

	return 0;
}

int __export rad_packet_change_str(struct rad_packet_t *pack, const char *vendor_name, const char *name, const char *val, int len)
{
	struct rad_attr_t *ra;

	ra = rad_packet_find_attr(pack, vendor_name, name);
	if (!ra)
		return -1;

	if (ra->len != len) {
		if (pack->len - ra->len + len >= REQ_LENGTH_MAX)
			return -1;

		ra->val.string = _realloc(ra->val.string, len + 1);
		if (!ra->val.string) {
			log_emerg("radius: out of memory\n");
			return -1;
		}

		ra->raw = ra->val.string;

		pack->len += len - ra->len;
		ra->len = len;
	}

	memcpy(ra->val.string, val, len);
	ra->val.string[len] = 0;

	return 0;
}

int __export rad_packet_add_val(struct rad_packet_t *pack, const char *vendor_name, const char *name, const char *val)
{
	struct rad_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_value_t *v;
	struct rad_dict_vendor_t *vendor;

	if (pack->len + (vendor_name ? 8 : 2) + 4 >= REQ_LENGTH_MAX)
		return -1;

	if (vendor_name) {
		vendor = rad_dict_find_vendor_name(vendor_name);
		if (!vendor)
			return -1;
		attr = rad_dict_find_vendor_attr(vendor, name);
	} else {
		vendor = NULL;
		attr = rad_dict_find_attr(name);
	}

	if (!attr)
		return -1;

	v = rad_dict_find_val_name(attr, val);
	if (!v)
		return -1;

	ra = mempool_alloc(attr_pool);
	if (!ra)
		return -1;

	memset(ra, 0, sizeof(*ra));
	ra->vendor = vendor;
	ra->attr = attr;
	ra->len = 4;
	ra->val = v->val;
	ra->raw = &ra->val;
	list_add_tail(&ra->entry, &pack->attrs);
	pack->len += (vendor_name ? 8 : 2) + 4;

	return 0;
}

int __export rad_packet_change_val(struct rad_packet_t *pack, const char *vendor_name, const char *name, const char *val)
{
	struct rad_attr_t *ra;
	struct rad_dict_value_t *v;

	ra = rad_packet_find_attr(pack, vendor_name, name);
	if (!ra)
		return -1;

	v = rad_dict_find_val_name(ra->attr, val);
	if (!v)
		return -1;

	ra->val = v->val;

	return 0;
}

int __export rad_packet_add_ipaddr(struct rad_packet_t *pack, const char *vendor_name, const char *name, in_addr_t ipaddr)
{
	return rad_packet_add_int(pack, vendor_name, name, ipaddr);
}

int rad_packet_add_ifid(struct rad_packet_t *pack, const char *vendor_name, const char *name, uint64_t ifid)
{
	struct rad_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (pack->len + (vendor_name ? 8 : 2) + 8 >= REQ_LENGTH_MAX)
		return -1;

	if (vendor_name) {
		vendor = rad_dict_find_vendor_name(vendor_name);
		if (!vendor)
			return -1;
		attr = rad_dict_find_vendor_attr(vendor, name);
	} else {
		vendor = NULL;
		attr = rad_dict_find_attr(name);
	}

	if (!attr)
		return -1;

	ra = mempool_alloc(attr_pool);
	if (!ra)
		return -1;

	memset(ra, 0, sizeof(*ra));
	ra->vendor = vendor;
	ra->attr = attr;
	ra->len = 8;
	ra->val.ifid = ifid;
	ra->raw = &ra->val;
	list_add_tail(&ra->entry, &pack->attrs);
	pack->len += (vendor_name ? 8 : 2) + 8;

	return 0;
}

int rad_packet_add_ipv6prefix(struct rad_packet_t *pack, const char *vendor_name, const char *name, struct in6_addr *prefix, int len)
{
	struct rad_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (pack->len + (vendor_name ? 8 : 2) + 18 >= REQ_LENGTH_MAX)
		return -1;

	if (vendor_name) {
		vendor = rad_dict_find_vendor_name(vendor_name);
		if (!vendor)
			return -1;
		attr = rad_dict_find_vendor_attr(vendor, name);
	} else {
		vendor = NULL;
		attr = rad_dict_find_attr(name);
	}

	if (!attr)
		return -1;

	ra = mempool_alloc(attr_pool);
	if (!ra)
		return -1;

	memset(ra, 0, sizeof(*ra));
	ra->vendor = vendor;
	ra->attr = attr;
	ra->len = 18;
	ra->val.ipv6prefix.len = len;
	ra->val.ipv6prefix.prefix = *prefix;
	ra->raw = &ra->val;
	list_add_tail(&ra->entry, &pack->attrs);
	pack->len += (vendor_name ? 8 : 2) + 18;

	return 0;
}


struct rad_attr_t __export *rad_packet_find_attr(struct rad_packet_t *pack, const char *vendor_name, const char *name)
{
	struct rad_attr_t *ra;
	struct rad_dict_vendor_t *vendor;

	if (vendor_name) {
		vendor = rad_dict_find_vendor_name(vendor_name);
		if (!vendor)
			return NULL;
	} else
		vendor = NULL;

	list_for_each_entry(ra, &pack->attrs, entry) {
		if (vendor && vendor != ra->vendor)
			continue;

		if (strcmp(ra->attr->name, name))
			continue;

		return ra;
	}

	return NULL;
}

int rad_packet_send(struct rad_packet_t *pack, int fd, struct sockaddr_in *addr)
{
	int n;

	clock_gettime(CLOCK_MONOTONIC, &pack->tv);

	if (pack->secret && pack->message_authenticator) {
		uint8_t hmac[HMAC_MD5_LEN];
		uint8_t *ptr = pack->buf;
		uint8_t *hmac_ptr = ptr + PACKET_SIGNED_OFFSET;
		if (hmac_md5((const uint8_t *)pack->secret, strlen((const char *)pack->secret), pack->buf, pack->len, hmac) < 0) {
			log_emerg("radius:packet: failed to calculate HMAC\n");
			return -1;
		}
		memcpy(hmac_ptr, hmac, HMAC_MD5_LEN);
	}


	while (1) {
		if (addr)
			n = sendto(fd, pack->buf, pack->len, 0, (struct sockaddr *)addr, sizeof(*addr));
		else
			n = write(fd, pack->buf, pack->len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_ppp_error("radius:write: %s\n", strerror(errno));
			return -1;
		} else if (n != pack->len) {
			log_ppp_error("radius:write: short write %i, excpected %i\n", n, pack->len);
			return -1;
		}
		break;
	}

	return 0;
}

static void init(void)
{
	attr_pool = mempool_create(sizeof(struct rad_attr_t));
	packet_pool = mempool_create(sizeof(struct rad_packet_t));
	buf_pool = mempool_create(REQ_LENGTH_MAX);
}

DEFINE_INIT(50, init);
