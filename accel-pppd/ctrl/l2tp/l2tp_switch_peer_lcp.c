#include "l2tp_switch_peer_test.h"

/* MD5(ident || secret || challenge), RFC 2661 section 5.1.1 */
void comp_chap_md5(uint8_t *md5, uint8_t ident,
			  const void *secret, size_t secret_len,
			  const void *chall, size_t chall_len)
{
	MD5_CTX md5_ctx;

	memset(md5, 0, MD5_DIGEST_LENGTH);
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &ident, sizeof(ident));
	MD5_Update(&md5_ctx, secret, secret_len);
	MD5_Update(&md5_ctx, chall, chall_len);
	MD5_Final(md5, &md5_ctx);
}

/* Returns non-zero only on fork/exec/pipe failure, the IPCP result is printed */
int run_real_ppp(int data_fd)
{
	int outpipe[2];
	pid_t pid;
	char buf[8192] = "";
	size_t used = 0;
	int ip_up = 0;
	time_t deadline;

	if (pipe(outpipe) < 0)
		return die("pipe() failed");

	pid = fork();
	if (pid < 0)
		return die("fork() failed");

	if (pid == 0) {
		char fdbuf[16];
		int flags;

		snprintf(fdbuf, sizeof(fdbuf), "%d", data_fd);

		dup2(outpipe[1], STDOUT_FILENO);
		dup2(outpipe[1], STDERR_FILENO);
		close(outpipe[0]);
		close(outpipe[1]);

		flags = fcntl(data_fd, F_GETFD);
		if (flags >= 0)
			fcntl(data_fd, F_SETFD, flags & ~FD_CLOEXEC);

		{
			char *child_argv[] = {
				"/usr/sbin/pppd",
				"plugin", "pppol2tp.so",
				"pppol2tp", fdbuf,
				"nodetach",
				"noauth",
				"debug",
				"novj", "novjccomp",
				"lcp-echo-interval", "0",
				"user", (char *)proxy_username,
				NULL,
			};
			execv(child_argv[0], child_argv);
		}
		_exit(127);
	}

	close(outpipe[1]);

	deadline = time(NULL) + 20;
	while (time(NULL) < deadline && used < sizeof(buf) - 1) {
		struct pollfd pfd = { .fd = outpipe[0], .events = POLLIN };
		int remaining_ms = (int)((deadline - time(NULL)) * 1000);
		ssize_t n;

		if (remaining_ms <= 0)
			break;
		if (poll(&pfd, 1, remaining_ms) <= 0)
			break;
		n = read(outpipe[0], buf + used, sizeof(buf) - 1 - used);
		if (n <= 0)
			break;
		used += (size_t)n;
		buf[used] = '\0';
		if (strstr(buf, "local  IP address") ||
		    strstr(buf, "local IP address")) {
			ip_up = 1;
			usleep(300000);
			struct pollfd pfd2 = { .fd = outpipe[0], .events = POLLIN };
			if (poll(&pfd2, 1, 500) > 0) {
				n = read(outpipe[0], buf + used,
					sizeof(buf) - 1 - used);
				if (n > 0) {
					used += (size_t)n;
					buf[used] = '\0';
				}
			}
			break;
		}
	}

	if (ip_up && hold_seconds > 0)
		sleep((unsigned int)hold_seconds);

	kill(pid, SIGTERM);
	{
		int waited_ms = 0;
		int reaped = 0;

		while (waited_ms < 2000 && !reaped) {
			reaped = waitpid(pid, NULL, WNOHANG) == pid;
			if (!reaped) {
				usleep(100000);
				waited_ms += 100;
			}
		}
		if (!reaped) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
		}
	}
	close(outpipe[0]);

	fputs(buf, stderr);
	printf("ppp_ip_up: %d\n", ip_up);

	return 0;
}

struct minimal_lcp_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

#define MINIMAL_PPP_LCP 0xc021
#define MINIMAL_PPP_PAP 0xc023
#define MINIMAL_PPP_CHAP 0xc223
#define MINIMAL_LCP_CONFREQ 1
#define MINIMAL_LCP_CONFACK 2
#define MINIMAL_LCP_RETRANSMIT_SECONDS 1
#define MINIMAL_LCP_OPT_AUTH 3
#define MINIMAL_CHAP_ALG_MD5 0x05

/* Never answers PAP, authentication comes from the ICCN proxy AVPs */
int run_minimal_lcp(int data_fd, int timeout_seconds)
{
	uint8_t buf[1500];
	uint8_t our_frame[sizeof(struct minimal_lcp_hdr) + 8];
	size_t our_frame_len;
	struct minimal_lcp_hdr our_req; /* buf is overwritten by each read */
	time_t deadline = time(NULL) + timeout_seconds;
	/* the first Configure-Request can be dropped before the splice is set up */
	time_t next_retransmit;
	int our_req_acked = 0, acked_a_peer_req = 0;

	our_req.proto = htons(MINIMAL_PPP_LCP);
	our_req.code = MINIMAL_LCP_CONFREQ;
	our_req.id = 1;
	our_req.len = htons(sizeof(our_req) - sizeof(our_req.proto));
	memcpy(our_frame, &our_req, sizeof(our_req));
	our_frame_len = sizeof(our_req);

	if (lcp_auth != LCP_AUTH_NONE) {
		uint8_t *opt = our_frame + our_frame_len;
		uint16_t proto = htons(lcp_auth == LCP_AUTH_PAP ?
				       MINIMAL_PPP_PAP : MINIMAL_PPP_CHAP);

		opt[0] = MINIMAL_LCP_OPT_AUTH;
		memcpy(opt + 2, &proto, sizeof(proto));
		opt[1] = 4;
		if (lcp_auth == LCP_AUTH_CHAP) {
			opt[4] = MINIMAL_CHAP_ALG_MD5;
			opt[1] = 5;
		}
		our_frame_len += opt[1];
		our_req.len = htons(our_frame_len - sizeof(our_req.proto));
		memcpy(our_frame, &our_req, sizeof(our_req));
	}

	if (write(data_fd, our_frame, our_frame_len) < 0) {
		fprintf(stderr, "run_minimal_lcp: initial Configure-Request"
			" write failed: %s\n", strerror(errno));
		return -1;
	}
	next_retransmit = time(NULL) + MINIMAL_LCP_RETRANSMIT_SECONDS;

	while (!(our_req_acked && acked_a_peer_req)) {
		struct pollfd pfd = { .fd = data_fd, .events = POLLIN };
		time_t now = time(NULL);
		time_t remaining = deadline - now;
		time_t poll_for;
		ssize_t n;

		if (remaining <= 0) {
			fprintf(stderr, "run_minimal_lcp: timed out waiting"
				" for LCP to open both ways (our_req_acked=%d"
				" acked_a_peer_req=%d)\n", our_req_acked,
				acked_a_peer_req);
			return -1;
		}

		poll_for = our_req_acked ? remaining : next_retransmit - now;
		if (poll_for < 0)
			poll_for = 0;
		if (poll_for > remaining)
			poll_for = remaining;

		if (poll(&pfd, 1, (int)(poll_for * 1000)) <= 0) {
			if (!our_req_acked && time(NULL) >= next_retransmit) {
				if (write(data_fd, our_frame, our_frame_len) < 0) {
					fprintf(stderr, "run_minimal_lcp:"
						" retransmitting Configure-Request"
						" failed: %s\n", strerror(errno));
					return -1;
				}
				next_retransmit = time(NULL) + MINIMAL_LCP_RETRANSMIT_SECONDS;
			}
			continue;
		}

		n = read(data_fd, buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "run_minimal_lcp: read failed: %s\n",
				strerror(errno));
			return -1;
		}
		if (n == 0) {
			fprintf(stderr, "run_minimal_lcp: peer closed the"
				" data socket\n");
			return -1;
		}
		if (n < (ssize_t)sizeof(struct minimal_lcp_hdr))
			continue;

		{
			struct minimal_lcp_hdr *hdr = (struct minimal_lcp_hdr *)buf;

			if (hdr->proto != htons(MINIMAL_PPP_LCP))
				continue;

			if (hdr->code == MINIMAL_LCP_CONFREQ) {
				hdr->code = MINIMAL_LCP_CONFACK;
				if (write(data_fd, buf, (size_t)n) < 0) {
					fprintf(stderr, "run_minimal_lcp: Configure-Ack"
						" write failed: %s\n", strerror(errno));
					return -1;
				}
				acked_a_peer_req = 1;
			} else if (hdr->code == MINIMAL_LCP_CONFACK &&
				  hdr->id == our_req.id) {
				our_req_acked = 1;
			}
		}
	}

	return 0;
}
