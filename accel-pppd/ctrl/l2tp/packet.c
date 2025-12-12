#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <openssl/md5.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "memdebug.h"
#include "utils.h"

#include "l2tp.h"
#include "attr_defs.h"

static mempool_t attr_pool;
static mempool_t pack_pool;
static mempool_t buf_pool;

void l2tp_packet_print(const struct l2tp_packet_t *pack,
		       void (*print)(const char *fmt, ...))
{
	const struct l2tp_attr_t *attr;
	const struct l2tp_dict_value_t *val;

	switch (pack->hdr.flags & L2TP_VER_MASK) {
	case 2:
		print("[L2TP tid=%u sid=%u", ntohs(pack->hdr.tid), ntohs(pack->hdr.sid));
		log_ppp_debug(" Ns=%u Nr=%u", ntohs(pack->hdr.Ns), ntohs(pack->hdr.Nr));
		break;
	case 3:
		print("[L2TP cid=%u", pack->hdr.cid);
		log_ppp_debug(" Ns=%u Nr=%u", ntohs(pack->hdr.Ns), ntohs(pack->hdr.Nr));
		break;
	default:
		print("[L2TP unknown version]\n");
		return;
	}

	list_for_each_entry(attr, &pack->attrs, entry) {
		print(" <%s", attr->attr->name);
		val = l2tp_dict_find_value(attr->attr, attr->val);
		if (val)
			print(" %s", val->name);
		else if (attr->H)
			print(" (hidden, %hu bytes)", attr->length);
		else {
			switch (attr->attr->type) {
				case ATTR_TYPE_INT16:
					print(" %i", attr->val.int16);
					break;
				case ATTR_TYPE_INT32:
					print(" %i", attr->val.int32);
					break;
				case ATTR_TYPE_STRING:
					print(" %s", attr->val.string);
					break;
			}
		}
		print(">");
	}

	print("]\n");
}

struct l2tp_packet_t *l2tp_packet_alloc(int ver, int msg_type,
					const struct sockaddr_in *addr, int H,
					const char *secret, size_t secret_len)
{
	struct l2tp_packet_t *pack = mempool_alloc(pack_pool);
	if (!pack)
		return NULL;

	memset(pack, 0, sizeof(*pack));
	INIT_LIST_HEAD(&pack->attrs);
	pack->hdr.flags = L2TP_FLAG_T | L2TP_FLAG_L | L2TP_FLAG_S | (ver & L2TP_VER_MASK);
	memcpy(&pack->addr, addr, sizeof(*addr));
	pack->hide_avps = H;
	pack->secret = secret;
	pack->secret_len = secret_len;

	if (msg_type) {
		if (l2tp_packet_add_int16(pack, Message_Type, msg_type, 1)) {
			mempool_free(pack);
			return NULL;
		}
	}

	return pack;
}

void l2tp_packet_free(struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr;

	while (!list_empty(&pack->attrs)) {
		attr = list_entry(pack->attrs.next, typeof(*attr), entry);
		if (attr->H || attr->attr->type == ATTR_TYPE_OCTETS
		    || attr->attr->type == ATTR_TYPE_STRING)
			_free(attr->val.octets);
		list_del(&attr->entry);
		mempool_free(attr);
	}

	mempool_free(pack);
}

static void memxor(uint8_t *dst, const uint8_t *src, size_t sz)
{
	const uintmax_t *umax_src = (const uintmax_t *)src;
	uintmax_t *umax_dst = (uintmax_t *)dst;
	size_t left = sz % sizeof(uintmax_t);
	size_t indx;

	for (indx = 0; indx < sz / sizeof(uintmax_t); ++indx)
		umax_dst[indx] ^= umax_src[indx];

	src += sz - left;
	dst += sz - left;
	while (left) {
		if (left >= sizeof(uint32_t)) {
			*(uint32_t *)dst ^= *(uint32_t *)src;
			src += sizeof(uint32_t);
			dst += sizeof(uint32_t);
			left -= sizeof(uint32_t);
		} else if (left >= sizeof(uint16_t)) {
			*(uint16_t *)dst ^= *(uint16_t *)src;
			src += sizeof(uint16_t);
			dst += sizeof(uint16_t);
			left -= sizeof(uint16_t);
		} else {
			*dst ^= *src;
			src += sizeof(uint8_t);
			dst += sizeof(uint8_t);
			left -= sizeof(uint8_t);
		}
	}
}

/*
 * Decipher hidden AVPs, keeping the Hidden AVP Subformat (i.e. the attribute
 * value is prefixed by 2 bytes indicating its length in network byte order).
 */
static int decode_avp(struct l2tp_avp_t *avp, const struct l2tp_attr_t *RV,
		      const char *secret, size_t secret_len)
{
	MD5_CTX md5_ctx;
	uint8_t md5[MD5_DIGEST_LENGTH];
	uint8_t p1[MD5_DIGEST_LENGTH];
	uint8_t *prev_block = NULL;
	uint16_t avp_len;
	uint16_t attr_len;
	uint16_t orig_attr_len;
	uint16_t bytes_left;
	uint16_t blocks_left;
	uint16_t last_block_len;

	avp_len = avp->flags & L2TP_AVP_LEN_MASK;
	if (avp_len < sizeof(struct l2tp_avp_t) + 2) {
		/* Hidden AVPs must contain at least two bytes
		   for storing original attribute length */
		log_warn("l2tp: incorrect hidden avp received (type %hu):"
			 " length too small (%hu bytes)\n",
			 ntohs(avp->type), avp_len);
		return -1;
	}
	attr_len = avp_len - sizeof(struct l2tp_avp_t);

	/* Decode first block */
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &avp->type, sizeof(avp->type));
	MD5_Update(&md5_ctx, secret, secret_len);
	MD5_Update(&md5_ctx, RV->val.octets, RV->length);
	MD5_Final(p1, &md5_ctx);

	if (attr_len <= MD5_DIGEST_LENGTH) {
		memxor(avp->val, p1, attr_len);
		return 0;
	}

	memxor(p1, avp->val, MD5_DIGEST_LENGTH);
	orig_attr_len = ntohs(*(uint16_t *)p1);

	if (orig_attr_len <= MD5_DIGEST_LENGTH - 2) {
		/* Enough bytes decoded already, no need to decode padding */
		memcpy(avp->val, p1, MD5_DIGEST_LENGTH);
		return 0;
	}

	if (orig_attr_len > attr_len - 2) {
		log_warn("l2tp: incorrect hidden avp received (type %hu):"
			 " original attribute length too big (ciphered"
			 " attribute length: %hu bytes, advertised original"
			 " attribute length: %hu bytes)\n",
			 ntohs(avp->type), attr_len, orig_attr_len);
		return -1;
	}

	/* Decode remaining blocks. Start from the last block as
	   preceding blocks must be kept hidden for computing MD5s */
	bytes_left = orig_attr_len + 2 - MD5_DIGEST_LENGTH;
	last_block_len = bytes_left % MD5_DIGEST_LENGTH;
	blocks_left = bytes_left / MD5_DIGEST_LENGTH;
	if (last_block_len) {
		prev_block = avp->val + blocks_left * MD5_DIGEST_LENGTH;
		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx, secret, secret_len);
		MD5_Update(&md5_ctx, prev_block, MD5_DIGEST_LENGTH);
		MD5_Final(md5, &md5_ctx);
		memxor(prev_block + MD5_DIGEST_LENGTH, md5, last_block_len);
		prev_block -= MD5_DIGEST_LENGTH;
	} else
		prev_block = avp->val + (blocks_left - 1) * MD5_DIGEST_LENGTH;

	while (prev_block >= avp->val) {
		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx, secret, secret_len);
		MD5_Update(&md5_ctx, prev_block, MD5_DIGEST_LENGTH);
		MD5_Final(md5, &md5_ctx);
		memxor(prev_block + MD5_DIGEST_LENGTH, md5, MD5_DIGEST_LENGTH);
		prev_block -= MD5_DIGEST_LENGTH;
	}
	memcpy(avp->val, p1, MD5_DIGEST_LENGTH);

	return 0;
}

int l2tp_recv(int fd, struct l2tp_packet_t **p, struct in_pktinfo *pkt_info,
	      const char *secret, size_t secret_len)
{
	struct l2tp_packet_t *pack;
	struct l2tp_hdr_t *hdr;
	struct l2tp_avp_t *avp;
	struct l2tp_attr_t *RV = NULL;
	struct sockaddr_in addr;
	socklen_t addr_len;
	uint16_t orig_avp_len;
	void *orig_avp_val;
	uint8_t *buf, *ptr;
	int n, length;

	*p = NULL;

	if (pkt_info) {
		struct msghdr msg;
		struct cmsghdr *cmsg;
		char msg_control[128];

		memset(&msg, 0, sizeof(msg));
		msg.msg_control = msg_control;
		msg.msg_controllen = sizeof(msg_control);

		n = recvmsg(fd, &msg, MSG_PEEK);
		if (n < 0) {
			if (errno == EAGAIN)
				return -1;
			log_error("l2tp: recvmsg: %s\n", strerror(errno));
			return 0;
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
				memcpy(pkt_info, CMSG_DATA(cmsg), sizeof(*pkt_info));
				break;
			}
		}
	}

	buf = mempool_alloc(buf_pool);
	if (!buf) {
		log_emerg("l2tp: out of memory\n");
		return 0;
	}
	hdr = (struct l2tp_hdr_t *)buf;
	ptr = (uint8_t *)(hdr + 1);

	addr_len = sizeof(addr);
	n = recvfrom(fd, buf, L2TP_MAX_PACKET_SIZE, 0, (struct sockaddr*)&addr, &addr_len);
	if (n < 0) {
		mempool_free(buf);
		if (errno == EAGAIN) {
			return -1;
		} else if (errno == ECONNREFUSED) {
			return -2;
		}
		log_error("l2tp: recv: %s\n", strerror(errno));
		return 0;
	}

	if (n < sizeof(*hdr)) {
		if (conf_verbose)
			log_warn("l2tp: short packet received (%i/%zu)\n", n, sizeof(*hdr));
		goto out_err_hdr;
	}

	hdr->flags = ntohs(hdr->flags);
	if (!(hdr->flags & L2TP_FLAG_T))
		goto out_err_hdr;
	if (!(hdr->flags & L2TP_FLAG_L)) {
		if (conf_verbose)
			log_warn("l2tp: incorrect control message received (L=0)\n");
		goto out_err_hdr;
	}
	if (!(hdr->flags & L2TP_FLAG_S)) {
		if (conf_verbose)
			log_warn("l2tp: incorrect control message received (S=0)\n");
		goto out_err_hdr;
	}
	switch (hdr->flags & L2TP_VER_MASK) {
	case 2:
		if (hdr->flags & L2TP_FLAG_O) {
			if (conf_verbose)
				log_warn("l2tp: incorrect control message received (O=1)\n");
			goto out_err_hdr;
		}
		break;
	case 3:
		break;
	default:
		if (conf_verbose)
			log_warn("l2tp: protocol version %i is not supported\n",
				 hdr->flags & L2TP_VER_MASK);
		goto out_err_hdr;
	}

	length = ntohs(hdr->length);
	if (length < sizeof(*hdr)) {
		if (conf_verbose)
			log_warn("l2tp: short packet received (%i/%zu)\n", length, sizeof(*hdr));
		goto out_err_hdr;
	} else if (n < length) {
		if (conf_verbose)
			log_warn("l2tp: short packet received (%i/%i)\n", n, length);
		goto out_err_hdr;
	}

	pack = mempool_alloc(pack_pool);
	if (!pack) {
		log_emerg("l2tp: out of memory\n");
		goto out_err_hdr;
	}

	memset(pack, 0, sizeof(*pack));
	INIT_LIST_HEAD(&pack->attrs);

	memcpy(&pack->addr, &addr, sizeof(addr));
	memcpy(&pack->hdr, hdr, sizeof(*hdr));
	length -= sizeof(*hdr);

	while (length > 0) {
		struct l2tp_dict_attr_t *da;
		struct l2tp_attr_t *attr;
		uint16_t avp_len;

		if (length < sizeof(*avp)) {
			if (conf_verbose)
				log_warn("l2tp: short avp received\n");
			goto out_err;
		}

		avp = (struct l2tp_avp_t *)ptr;
		avp->flags = ntohs(avp->flags);
		avp_len = avp->flags & L2TP_AVP_LEN_MASK;
		if (avp_len < sizeof(*avp)) {
			if (conf_verbose)
				log_warn("l2tp: short avp received\n");
			goto out_err;
		} else if (length < avp_len) {
			if (conf_verbose)
				log_warn("l2tp: incorrect avp received (exceeds message length)\n");
			goto out_err;
		}

		if (avp->vendor)
			goto skip;

		da = l2tp_dict_find_attr_by_id(ntohs(avp->type));
		if (!da) {
			if (conf_verbose) {
				log_warn("l2tp: unknown avp received (type=%i, M=%u)\n",
					 ntohs(avp->type), !!(avp->flags & L2TP_AVP_FLAG_M));
			}
			if ((avp->flags & L2TP_AVP_FLAG_M) && !conf_avp_permissive)
				goto out_err;
		} else {
			if (da->M != -1 && !da->M != !(avp->flags & L2TP_AVP_FLAG_M)) {
				if (conf_verbose) {
					log_warn("l2tp: incorrect avp received (type=%i, M=%i, must be %i)\n",
						 ntohs(avp->type), !!(avp->flags & L2TP_AVP_FLAG_M), da->M);
				}
				if (!conf_avp_permissive)
				    goto out_err;
			}

			if (da->H != -1 && !da->H != !(avp->flags & L2TP_AVP_FLAG_H)) {
				if (conf_verbose) {
					log_warn("l2tp: incorrect avp received (type=%i, H=%i, must be %i)\n",
						 ntohs(avp->type), !!(avp->flags & L2TP_AVP_FLAG_H), da->H);
				}
				if (!conf_avp_permissive)
				    goto out_err;
			}

			if (avp->flags & L2TP_AVP_FLAG_H) {
				if (!RV) {
					if (conf_verbose)
						log_warn("l2tp: incorrect avp received (type=%i, H=1, but Random-Vector is not received)\n", ntohs(avp->type));
					goto out_err;
				}
				if (secret == NULL || secret_len == 0) {
					log_error("l2tp: impossible to decode"
						  " hidden avp (type %hu): no"
						  " secret set)\n",
						  ntohs(avp->type));
					goto out_err;
				}
				if (decode_avp(avp, RV, secret, secret_len) < 0)
					goto out_err;

				orig_avp_len = ntohs(*(uint16_t *)avp->val) + sizeof(*avp);
				orig_avp_val = avp->val + sizeof(uint16_t);
			} else {
				orig_avp_len = avp_len;
				orig_avp_val = avp->val;
			}

			attr = mempool_alloc(attr_pool);
			memset(attr, 0, sizeof(*attr));
			attr->attr = da;
			attr->M = !!(avp->flags & L2TP_AVP_FLAG_M);
			attr->H = 0;
			attr->length = orig_avp_len - sizeof(*avp);
			list_add_tail(&attr->entry, &pack->attrs);

			if (attr->attr->id == Random_Vector)
				RV = attr;

			switch (da->type) {
				case ATTR_TYPE_INT16:
					if (orig_avp_len != sizeof(*avp) + 2)
						goto out_err_len;
					attr->val.uint16 = ntohs(*(uint16_t *)orig_avp_val);
					break;
				case ATTR_TYPE_INT32:
					if (orig_avp_len != sizeof(*avp) + 4)
						goto out_err_len;
					attr->val.uint32 = ntohl(*(uint32_t *)orig_avp_val);
					break;
				case ATTR_TYPE_INT64:
					if (orig_avp_len != sizeof(*avp) + 8)
						goto out_err_len;
					attr->val.uint64 = be64toh(*(uint64_t *)orig_avp_val);
					break;
				case ATTR_TYPE_OCTETS:
					attr->val.octets = _malloc(attr->length);
					if (!attr->val.octets)
						goto out_err_mem;
					memcpy(attr->val.octets, orig_avp_val, attr->length);
					break;
				case ATTR_TYPE_STRING:
					attr->val.string = _malloc(attr->length + 1);
					if (!attr->val.string)
						goto out_err_mem;
					memcpy(attr->val.string, orig_avp_val, attr->length);
					attr->val.string[attr->length] = 0;
					break;
			}
		}
skip:
		ptr += avp_len;
		length -= avp_len;
	}

	*p = pack;

	mempool_free(buf);

	return 0;

out_err:
	l2tp_packet_free(pack);
out_err_hdr:
	mempool_free(buf);
	return 0;
out_err_len:
	if (conf_verbose)
		log_warn("l2tp: incorrect avp received (type=%i, incorrect length %i)\n", ntohs(avp->type), orig_avp_len);
	goto out_err;
out_err_mem:
	log_emerg("l2tp: out of memory\n");
	goto out_err;
}

int l2tp_packet_send(int sock, struct l2tp_packet_t *pack)
{
	struct l2tp_hdr_t *hdr;
	struct l2tp_avp_t *avp;
	struct l2tp_attr_t *attr;
	uint8_t *buf, *ptr;
	int n, len;

	buf = mempool_alloc(buf_pool);
	if (!buf) {
		log_emerg("l2tp: out of memory\n");
		return -1;
	}

	memset(buf, 0, L2TP_MAX_PACKET_SIZE);
	hdr = (struct l2tp_hdr_t *)buf;
	ptr = (uint8_t *)(hdr + 1);
	len = sizeof(pack->hdr);

	list_for_each_entry(attr, &pack->attrs, entry) {
		if (len + sizeof(*avp) + attr->length >= L2TP_MAX_PACKET_SIZE) {
			log_error("l2tp: cann't send packet (exceeds maximum size)\n");
			mempool_free(buf);
			return -1;
		}
		avp = (struct l2tp_avp_t *)ptr;
		avp->type = htons(attr->attr->id);
		avp->flags = htons((attr->M ? L2TP_AVP_FLAG_M : 0) |
				   (attr->H ? L2TP_AVP_FLAG_H : 0) |
				   ((sizeof(*avp) + attr->length) & L2TP_AVP_LEN_MASK));
		if (attr->H)
			memcpy(avp->val, attr->val.octets, attr->length);
		else
			switch (attr->attr->type) {
			case ATTR_TYPE_INT16:
				*(int16_t *)avp->val = htons(attr->val.int16);
				break;
			case ATTR_TYPE_INT32:
				*(int32_t *)avp->val = htonl(attr->val.int32);
				break;
			case ATTR_TYPE_INT64:
				*(uint64_t *)avp->val = htobe64(attr->val.uint64);
				break;
			case ATTR_TYPE_STRING:
			case ATTR_TYPE_OCTETS:
				memcpy(avp->val, attr->val.string, attr->length);
				break;
			}
		ptr += sizeof(*avp) + attr->length;
		len += sizeof(*avp) + attr->length;
	}

	pack->hdr.length = htons(len);
	memcpy(buf, &pack->hdr, sizeof(pack->hdr));
	hdr->flags = htons(pack->hdr.flags);

	n = sendto(sock, buf, len, 0, (struct sockaddr*)&pack->addr, sizeof(pack->addr));
	mempool_free(buf);

	if (n < 0) {
		if (errno == EAGAIN) {
			if (conf_verbose)
				log_warn("l2tp: buffer overflow (packet lost)\n");
		} else {
			if (conf_verbose)
				log_warn("l2tp: sendto: %s\n", strerror(errno));
			return -1;
		}
	}

	if (n != len) {
		if (conf_verbose)
			log_warn("l2tp: short write (%i/%i)\n", n, len);
	}

	return 0;
}

int encode_attr(const struct l2tp_packet_t *pack, struct l2tp_attr_t *attr,
		const void *val, uint16_t val_len)
{
	uint8_t *u8_ptr = NULL;
	uint8_t md5[MD5_DIGEST_LENGTH];
	MD5_CTX md5_ctx;
	uint16_t pad_len;
	uint16_t attr_type;
	uint16_t blocks_left;
	uint16_t last_block_len;
	int err;

	if (pack->secret == NULL || pack->secret_len == 0) {
		log_error("l2tp: impossible to hide AVP: no secret\n");
		goto err;
	}
	if (pack->last_RV == NULL) {
		log_error("l2tp: impossible to hide AVP: no random vector\n");
		goto err;
	}

	if (u_randbuf(&pad_len, sizeof(pad_len), &err) < 0) {
		if (err)
			log_error("l2tp: impossible to hide AVP:"
				  " reading from urandom failed: %s\n",
				  strerror(err));
		else
			log_error("l2tp: impossible to hide AVP:"
				  " end of file reached while reading"
				  " from urandom\n");
		goto err;
	}
	/* Use at least 16 bytes of padding */
	pad_len = (pad_len & 0x007F) + 16;

	/* Generate Hidden AVP Subformat:
	 *   -original AVP size (2 bytes, network byte order)
	 *   -original AVP value ('val_len' bytes)
	 *   -padding ('pad_len' bytes of random values)
	 */
	attr->length = sizeof(val_len) + val_len + pad_len;
	attr->val.octets = _malloc(attr->length);
	if (attr->val.octets == NULL) {
		log_error("l2tp: impossible to hide AVP:"
			  " memory allocation failed\n");
		goto err;
	}

	*(uint16_t *)attr->val.octets = htons(val_len);
	memcpy(attr->val.octets + sizeof(val_len), val, val_len);

	if (u_randbuf(attr->val.octets + sizeof(val_len) + val_len,
		      pad_len, &err) < 0) {
		if (err)
			log_error("l2tp: impossible to hide AVP:"
				  " reading from urandom failed: %s\n",
				  strerror(err));
		else
			log_error("l2tp: impossible to hide AVP:"
				  " end of file reached while reading"
				  " from urandom\n");
		goto err_free;
	}

	/* Hidden AVP cipher:
	 * ciphered[0] = clear[0] xor MD5(attr_type, secret, RV)
	 * ciphered[1] = clear[1] xor MD5(secret, ciphered[0])
	 * ...
	 * ciphered[n] = clear[n] xor MD5(secret, ciphered[n-1])
	 */
	attr_type = htons(attr->attr->id);
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &attr_type, sizeof(attr_type));
	MD5_Update(&md5_ctx, pack->secret, pack->secret_len);
	MD5_Update(&md5_ctx, pack->last_RV->val.octets, pack->last_RV->length);
	MD5_Final(md5, &md5_ctx);

	if (attr->length <= MD5_DIGEST_LENGTH) {
		memxor(attr->val.octets, md5, attr->length);
		return 0;
	}

	memxor(attr->val.octets, md5, MD5_DIGEST_LENGTH);

	blocks_left = attr->length / MD5_DIGEST_LENGTH - 1;
	last_block_len = attr->length % MD5_DIGEST_LENGTH;

	for (u8_ptr = attr->val.octets; blocks_left; --blocks_left) {
		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx, pack->secret, pack->secret_len);
		MD5_Update(&md5_ctx, u8_ptr, MD5_DIGEST_LENGTH);
		MD5_Final(md5, &md5_ctx);
		u8_ptr += MD5_DIGEST_LENGTH;
		memxor(u8_ptr, md5, MD5_DIGEST_LENGTH);
	}

	if (last_block_len) {
		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx, pack->secret, pack->secret_len);
		MD5_Update(&md5_ctx, u8_ptr, MD5_DIGEST_LENGTH);
		MD5_Final(md5, &md5_ctx);
		memxor(u8_ptr + MD5_DIGEST_LENGTH, md5, last_block_len);
	}

	return 0;

err_free:
	_free(attr->val.octets);
	attr->val.octets = NULL;
err:
	return -1;
}

static struct l2tp_attr_t *attr_alloc(int id, int M, int H)
{
	struct l2tp_attr_t *attr;
	struct l2tp_dict_attr_t *da;

	da = l2tp_dict_find_attr_by_id(id);
	if (!da)
		return NULL;

	attr = mempool_alloc(attr_pool);
	if (!attr) {
		log_emerg("l2tp: out of memory\n");
		return NULL;
	}

	memset(attr, 0, sizeof(*attr));

	attr->attr = da;

	if (da->M != -1)
		attr->M = da->M;
	else
		attr->M = M;

	if (da->H != -1)
		attr->H = da->H;
	else
		attr->H = H;

	return attr;
}

static int l2tp_packet_add_random_vector(struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr = attr_alloc(Random_Vector, 1, 0);
	uint16_t ranvec_len;
	int err;

	if (!attr)
		goto err;

	if (u_randbuf(&ranvec_len, sizeof(ranvec_len), &err) < 0) {
		if (err)
			log_error("l2tp: impossible to build Random Vector:"
				  " reading from urandom failed: %s\n",
				  strerror(err));
		else
			log_error("l2tp: impossible to build Random Vector:"
				  " end of file reached while reading"
				  " from urandom\n");
		goto err_attr;
	}
	/* RFC 2661 recommends that Random Vector be least 16 bytes long */
	ranvec_len = (ranvec_len & 0x007F) + 16;

	attr->length = ranvec_len;
	attr->val.octets = _malloc(ranvec_len);
	if (!attr->val.octets) {
		log_emerg("l2tp: out of memory\n");
		goto err_attr;
	}

	if (u_randbuf(attr->val.octets, ranvec_len, &err) < 0) {
		if (err)
			log_error("l2tp: impossible to build Random Vector:"
				  " reading from urandom failed: %s\n",
				  strerror(err));
		else
			log_error("l2tp: impossible to build Random Vector:"
				  " end of file reached while reading"
				  " from urandom\n");
		goto err_attr_val;
	}

	list_add_tail(&attr->entry, &pack->attrs);
	pack->last_RV = attr;

	return 0;

err_attr_val:
	_free(attr->val.octets);
err_attr:
	mempool_free(attr);
err:
	return -1;
}

int l2tp_packet_add_int16(struct l2tp_packet_t *pack, int id, int16_t val, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M, pack->hide_avps);

	if (!attr)
		return -1;

	if (attr->H) {
		if (pack->last_RV == NULL)
			if (l2tp_packet_add_random_vector(pack) < 0)
				goto err;
		val = htons(val);
		if (encode_attr(pack, attr, &val, sizeof(val)) < 0)
			goto err;
	} else {
		attr->length = sizeof(val);
		attr->val.int16 = val;
	}
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;

err:
	mempool_free(attr);
	return -1;
}

int l2tp_packet_add_int32(struct l2tp_packet_t *pack, int id, int32_t val, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M, pack->hide_avps);

	if (!attr)
		return -1;

	if (attr->H) {
		if (pack->last_RV == NULL)
			if (l2tp_packet_add_random_vector(pack) < 0)
				goto err;
		val = htonl(val);
		if (encode_attr(pack, attr, &val, sizeof(val)) < 0)
			goto err;
	} else {
		attr->length = sizeof(val);
		attr->val.int32 = val;
	}
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;

err:
	mempool_free(attr);
	return -1;
}

int l2tp_packet_add_int64(struct l2tp_packet_t *pack, int id, int64_t val, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M, pack->hide_avps);

	if (!attr)
		return -1;

	if (attr->H) {
		if (pack->last_RV == NULL)
			if (l2tp_packet_add_random_vector(pack) < 0)
				goto err;
		val = htobe64(val);
		if (encode_attr(pack, attr, &val, sizeof(val)) < 0)
			goto err;
	} else {
		attr->length = sizeof(val);
		attr->val.uint64 = val;
	}
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;

err:
	mempool_free(attr);
	return -1;
}

int l2tp_packet_add_string(struct l2tp_packet_t *pack, int id, const char *val, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M, pack->hide_avps);
	size_t val_len = strlen(val);

	if (!attr)
		return -1;

	if (attr->H) {
		if (pack->last_RV == NULL)
			if (l2tp_packet_add_random_vector(pack) < 0)
				goto err;
		if (encode_attr(pack, attr, val, val_len) < 0)
			goto err;
	} else {
		attr->length = val_len;
		attr->val.string = _strdup(val);
		if (!attr->val.string) {
			log_emerg("l2tp: out of memory\n");
			goto err;
		}
	}
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;

err:
	mempool_free(attr);
	return -1;
}

int l2tp_packet_add_octets(struct l2tp_packet_t *pack, int id, const uint8_t *val, int size, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M, pack->hide_avps);

	if (!attr)
		return -1;

	if (size == 0) {
		attr->length = size;
		attr->val.octets = NULL;
	} else if (attr->H) {
		if (pack->last_RV == NULL)
			if (l2tp_packet_add_random_vector(pack) < 0)
				goto err;
		if (encode_attr(pack, attr, val, size) < 0)
			goto err;
	} else {
		attr->length = size;
		attr->val.octets = _malloc(size);
		if (!attr->val.octets) {
			log_emerg("l2tp: out of memory\n");
			goto err;
		}
		memcpy(attr->val.octets, val, attr->length);
	}
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;

err:
	mempool_free(attr);
	return -1;
}

static void init(void)
{
	attr_pool = mempool_create(sizeof(struct l2tp_attr_t));
	pack_pool = mempool_create(sizeof(struct l2tp_packet_t));
	buf_pool = mempool_create(L2TP_MAX_PACKET_SIZE);
}

DEFINE_INIT(21, init);
