#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT "2001"

#define EXIT_STRING "exit\n"
#define LN_EXIT_STRING "\nexit\n"
#define DEFAULT_BUFSIZE 1500

struct host_params {
	const char *str_addr;
	const char *str_port;
	char *passwd;
	sa_family_t family;
	int fd;
};

enum exit_status {
	XSTATUS_SYNTAX = 1,
	XSTATUS_BADPARAM,
	XSTATUS_CONNFAIL,
	XSTATUS_TIMEOUT,
	XSTATUS_ARGVLEN,
	XSTATUS_INTERNAL = 100
};

static bool verbose = false;

static int fverbf(FILE *stream, const char *format, ...)
	__attribute__((format(gnu_printf, 2, 3)));

static int fverbf(FILE *stream, const char *format, ...)
{
	va_list ap;
	int rv = 0;

	if (verbose) {
		va_start(ap, format);
		rv = vfprintf(stream, format, ap);
		va_end(ap);
	}

	return rv;
}

static int fd_addflg(int fd, int add_flg, int *orig_flg)
{
	int flg;

	flg = fcntl(fd, F_GETFL);
	if (flg < 0) {
		fprintf(stderr, "%s,%i:"
			" Impossible to get flags of file descriptor %i:"
			" fcntl(F_GETFL) failed: %s\n",
			__func__, __LINE__, fd, strerror(errno));
		return -1;
	}
	if (flg & add_flg)
		return 0;

	flg = fcntl(fd, F_SETFL, flg | add_flg);
	if (flg < 0) {
		fprintf(stderr, "%s,%i:"
			" Impossible to set flags of file descriptor %i:"
			" fcntl(F_SETFL, %i) failed: %s\n",
			__func__, __LINE__,
			fd, flg | add_flg, strerror(errno));
		return -1;
	}

	if (orig_flg)
		*orig_flg = flg;

	return 0;
}

static int fd_restoreflg(int fd, int flg)
{
	if (fcntl(fd, F_SETFL, flg) < 0) {
		fprintf(stderr, "%s,%i:"
			" Impossible to restore flags of file descriptor %i:"
			" fcntl(F_SETFL, %i) failed: %s\n",
			__func__, __LINE__, fd, flg, strerror(errno));
		return -1;
	}

	return 0;
}

static char get_msghdr_last_char(const struct msghdr *mhdr)
{
	struct iovec *iov = mhdr->msg_iov + mhdr->msg_iovlen - 1;
	uint8_t *last_buf = iov->iov_base;
	size_t last_buf_len = iov->iov_len;

	return last_buf[last_buf_len - 1];
}

static ssize_t accel_sendmsg(int fd, const struct msghdr *mhdr)
{
	ssize_t sndlen;

	sndlen = sendmsg(fd, mhdr, 0);
	if (sndlen < 0) {
		if (errno == EAGAIN || errno == EINTR || errno == EMSGSIZE) {
			int err = errno;
			fverbf(stderr, "%s,%i: Impossible to send message:"
			       " sendmsg() failed: %s\n",
			       __func__, __LINE__, strerror(errno));
			return (err == EMSGSIZE) ? -1 : 0;
		} else {
			fprintf(stderr, "%s,%i: Impossible to send message:"
				" sendmsg() failed: %s\n",
				__func__, __LINE__, strerror(errno));
			return -2;
		}
	}

	return sndlen;
}

static ssize_t accel_send(int fd, const void *buf, size_t buflen)
{
	ssize_t sndlen;

	sndlen = send(fd, buf, buflen, 0);
	if (sndlen < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			fverbf(stderr, "%s,%i: Impossible to send command:"
			       " send() failed: %s\n",
			       __func__, __LINE__, strerror(errno));
			return 0;
		} else {
			fprintf(stderr, "%s,%i: Impossible to send command:"
				" send() failed: %s\n",
				__func__, __LINE__, strerror(errno));
			return -1;
		}
	}

	return sndlen;
}

static ssize_t accel_read(int fd, void *buf, size_t buflen)
{
	ssize_t res;

	res = read(fd, buf, buflen);
	if (res < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			fverbf(stderr, "%s,%i: Impossible to read input:"
			       " read() failed: %s\n",
			       __func__, __LINE__, strerror(errno));
			return 0;
		} else {
			fprintf(stderr, "%s,%i: Impossible to read input:"
				" read() failed: %s\n",
				__func__, __LINE__, strerror(errno));
			return -2;
		}
	} else if (res == 0)
		return -1;

	return res;
}

static int accel_talk(int cmdfd, int accelfd, const struct msghdr *mhdr,
		      const struct timespec *timeout)
{
	uint8_t printbuf[DEFAULT_BUFSIZE] = { 0 };
	uint8_t transbuf[DEFAULT_BUFSIZE] = { 0 };
	int fdmax;
	fd_set rfds;
	fd_set wfds;
	ssize_t res;
	char last_char = '\0';
	int cmdflg = -1;
	int accelflg = -1;
	size_t bytes_rd = 0;
	size_t bytes_wr = 0;
	bool start_read = false;
	bool exit_sent = false;
	int err;

	/* Set non-block flag to file descriptors: in some cases, read() may
	   block even if select() reported the file descriptor to be ready */
	if (cmdfd >= 0) {
		if (fd_addflg(cmdfd, O_NONBLOCK, &cmdflg) < 0) {
			err = XSTATUS_INTERNAL;
			goto out;
		}
	}
	if (fd_addflg(accelfd, O_NONBLOCK, &accelflg) < 0) {
		err = XSTATUS_INTERNAL;
		goto out;
	}

	for (;;) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		fdmax = -1;

		if (mhdr == NULL && cmdfd < 0 && bytes_wr == bytes_rd
		    && start_read && !exit_sent) {
			/* Nothing to read anymore and all data have
			   been sent. Send "exit" so that accel-ppp
			   will disconnect after sending responses. */
			if (last_char == '\n') {
				memcpy(transbuf, EXIT_STRING,
				       strlen(EXIT_STRING));
				bytes_rd = strlen(EXIT_STRING);
			} else {
				memcpy(transbuf, LN_EXIT_STRING,
				       strlen(LN_EXIT_STRING));
				bytes_rd = strlen(LN_EXIT_STRING);
			}
			bytes_wr = 0;
			exit_sent = true;
		}

		if (mhdr || bytes_wr < bytes_rd) {
			/* Data need to be sent to accel-ppp */
			FD_SET(accelfd, &wfds);
			fdmax = (accelfd > fdmax) ? accelfd : fdmax;
		}
		if (start_read) {
			/* Wait for data from accel-ppp */
			FD_SET(accelfd, &rfds);
			fdmax = (accelfd > fdmax) ? accelfd : fdmax;
		}
		if (cmdfd >= 0 && bytes_rd < sizeof(transbuf)) {
			/* Forward data from input stream to accel-ppp */
			FD_SET(cmdfd, &rfds);
			fdmax = (cmdfd > fdmax) ? cmdfd : fdmax;
		}

		if (fdmax == -1) {
			fverbf(stderr, "%s,%i: All I/O completed\n",
			       __func__, __LINE__);
			err = EXIT_SUCCESS;
			break;
		}

		res = pselect(fdmax + 1, &rfds, &wfds, NULL, timeout, NULL);
		if (res <= 0) {
			if (res < 0) {
				if (errno == EINTR) {
					fverbf(stderr, "%s,%i: I/O error:"
					       " pselect() failed: %s\n",
					       __func__, __LINE__,
					       strerror(errno));
					continue;
				}
				fprintf(stderr, "%s,%i: I/O error:"
					" pselect() failed: %s\n",
					__func__, __LINE__, strerror(errno));
				err = XSTATUS_INTERNAL;
			} else
				err = XSTATUS_TIMEOUT;
			break;
		}

		if (FD_ISSET(accelfd, &wfds)) {
			/* Send request to accel-ppp */
			res = 0;
			if (mhdr) {
				res = accel_sendmsg(accelfd, mhdr);
				if (res < 0) {
					if (res == -1)
						err = XSTATUS_ARGVLEN;
					else
						err = XSTATUS_INTERNAL;
					break;
				} else if (res != 0) {
					/* Message sent, don't send it again */
					last_char = get_msghdr_last_char(mhdr);
					mhdr = NULL;
				}
			} else if (bytes_wr < bytes_rd) {
				res = accel_send(accelfd, transbuf + bytes_wr,
						 bytes_rd - bytes_wr);
				if (res < 0) {
					err = XSTATUS_INTERNAL;
					break;
				}
				bytes_wr += res;
				if (bytes_wr == bytes_rd) {
					/* No important data left in buffer,
					   reuse space */
					bytes_wr = 0;
					bytes_rd = 0;
				}
			}
			if (res > 0)
				/* Start reading accel-ppp's response
				   as soon as data have been sent */
				start_read = true;
		}

		if (FD_ISSET(accelfd, &rfds)) {
			/* Read answer from accel-ppp */
			res = accel_read(accelfd, printbuf,
					 sizeof(printbuf) - 1);
			if (res < 0) {
				if (res == -1) {
					fverbf(stderr,
					       "%s,%i: Communication with"
					       " accel-ppp closed\n",
					       __func__, __LINE__);
					err = EXIT_SUCCESS;
				} else
					err = XSTATUS_INTERNAL;
				break;
			} else if (res != 0) {
				printbuf[res] = '\0';
				fprintf(stdout, "%s", printbuf);
				fflush(stdout);
			}
		}

		if (cmdfd >= 0 && FD_ISSET(cmdfd, &rfds)) {
			/* Read commands from input stream */
			res = accel_read(cmdfd, transbuf + bytes_rd,
					 sizeof(transbuf) - bytes_rd);
			if (res < 0) {
				if (res == -1) {
					fverbf(stderr,
					       "%s,%i: Communication with"
					       " input stream closed\n",
					       __func__, __LINE__);
					fd_restoreflg(cmdfd, cmdflg);
					cmdfd = -1;
				} else {
					err = XSTATUS_INTERNAL;
					break;
				}
			} else if (res != 0) {
				bytes_rd += res;
				last_char = transbuf[bytes_rd - 1];
			}
		}
	}

out:
	if (cmdfd >= 0 && cmdflg >= 0)
		fd_restoreflg(cmdfd, cmdflg);
	if (accelflg >= 0)
		fd_restoreflg(accelfd, accelflg);

	return err;
}

static struct msghdr *argv_to_msghdr(int argc, char * const *argv, const char *passwd)
{
	struct msghdr *mh = NULL;
	struct iovec *iv = NULL;
	int indx, ividx = 0, ivlen = 0;

	if (passwd && *passwd)
		ivlen += 2;
	if (argc)
		ivlen += argc * 2 - 1;

	mh = calloc(1, sizeof(struct msghdr));
	if (mh == NULL) {
		fprintf(stderr, "%s,%i: Impossible to allocate buffer:"
			" calloc() failed: %s\n",
			__func__, __LINE__, strerror(errno));
		return NULL;
	}
	iv = calloc(ivlen, sizeof(struct iovec));
	if (iv == NULL) {
		fprintf(stderr, "%s,%i: Impossible to allocate buffer:"
			" calloc() failed: %s\n",
			__func__, __LINE__, strerror(errno));
		free(mh);
		return NULL;
	}

	if (passwd && *passwd) {
		iv[ividx].iov_base = (void *) passwd;
		iv[ividx++].iov_len = strlen(passwd);
		iv[ividx].iov_base = "\n";
		iv[ividx++].iov_len = 1;
	}
	for (indx = 0; indx < argc; ++indx) {
		if (indx) {
		    iv[ividx].iov_base = " ";
		    iv[ividx++].iov_len = 1;
		}
		iv[ividx].iov_base = argv[indx];
		iv[ividx++].iov_len = strlen(argv[indx]);
	}

	mh->msg_iov = iv;
	mh->msg_iovlen = ivlen;

	return mh;
}

static void msghdr_free(struct msghdr *mh)
{
	if (mh) {
		free(mh->msg_iov);
		free(mh);
	}
}

static int accel_connect(struct host_params *peer, bool numeric)
{
	struct addrinfo *res = NULL;
	struct addrinfo *ai = NULL;
	struct addrinfo hints;
	int fd;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = peer->family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	if (numeric)
		hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;

	rv = getaddrinfo(peer->str_addr, peer->str_port, &hints, &res);
	if (rv != 0) {
		int err = errno;

		if (rv == EAI_NONAME)
			if (numeric)
				fprintf(stderr,
					"Either host \"%s\" is not a valid IP"
					" address, or \"%s\" is not a valid"
					" port number\n",
					peer->str_addr, peer->str_port);
			else
				fprintf(stderr,
					"Can't resolve host \"%s\" or port"
					" \"%s\"\n",
					peer->str_addr, peer->str_port);
		else if (rv == EAI_NODATA)
			fprintf(stderr,
				"Host \"%s\" doesn't have any IP address\n",
				peer->str_addr);
		else if (numeric && rv == EAI_ADDRFAMILY)
			fprintf(stderr, "\"%s\" is not a valid %s address\n",
				peer->str_addr,
				(peer->family == AF_INET) ? "IPv4" : "IPv6");

		if (rv == EAI_NONAME || rv == EAI_NODATA
		    || (numeric && rv == EAI_ADDRFAMILY)) {
			fverbf(stderr, "%s,%i:"
			       " Impossible to get address of \"%s:%s\":"
			       " getaddrinfo() failed: %s\n",
			       __func__, __LINE__,
			       peer->str_addr, peer->str_port,
			       gai_strerror(rv));
			return XSTATUS_BADPARAM;
		} else {
			fprintf(stderr, "%s,%i:"
				" Impossible to get address of \"%s:%s\":"
				" getaddrinfo() failed: %s\n",
				__func__, __LINE__,
				peer->str_addr, peer->str_port,
				(rv == EAI_SYSTEM)
				? strerror(err) : gai_strerror(rv));
			return XSTATUS_INTERNAL;
		}
	}

	for (ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family,
			    ai->ai_socktype,
			    ai->ai_protocol);
		if (fd < 0) {
			fverbf(stderr, "%s,%i:"
			       " Impossible to create socket %i,%i,%i:"
			       " socket() failed: %s\n",
			       __func__, __LINE__,
			       ai->ai_family,
			       ai->ai_socktype,
			       ai->ai_protocol, strerror(errno));
			continue;
		}
		int ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
		if (ret == -1) {
			fverbf(stderr, "%s,%i:"
			       " fcntl() failed on setting FD_CLOEXEC: %s\n",
			       __func__, __LINE__,
			       strerror(errno));
			continue;
		}
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			fverbf(stderr, "%s,%i: connect() failed: %s\n",
			       __func__, __LINE__, strerror(errno));
			close(fd);
			continue;
		}
		break;
	}

	freeaddrinfo(res);

	if (ai == NULL)
		return XSTATUS_CONNFAIL;

	peer->fd = fd;

	return EXIT_SUCCESS;
}

static int set_timespec(struct timespec *timeout, const char *str)
{
	char *end = NULL;
	unsigned long ulong;

	if (*str == '\0' || strchr(str, '-'))
		return -1;

	errno = 0;
	ulong = strtoul(str, &end, 0);
	if (errno != 0)
		return -1;
	if (*end == '\0' || strcmp(end, "s") == 0) {
		timeout->tv_sec = ulong;
		timeout->tv_nsec = 0;
	} else if (strcmp(end, "ms") == 0) {
		timeout->tv_sec = ulong / 1000;
		timeout->tv_nsec = (ulong % 1000) * 1000;
	} else if (strcmp(end, "us") == 0) {
		timeout->tv_sec = ulong / 1000000;
		timeout->tv_nsec = (ulong % 1000000) * 1000;
	} else {
		return -1;
	}

	return 0;
}

static void print_version(FILE *stream)
{
	fprintf(stream, "accel-cmd %s\n", ACCEL_PPP_VERSION);
}

static void print_usage(FILE *stream, const char *name)
{
	fprintf(stream, "Usage:\t%s [-v] [-4] [-6] [-n]"
		" [-f FAMILY] [-H HOST] [-p PORT]"
		" [-t TIMEOUT] [COMMAND]\n", name);
}

static void print_help(const char *name)
{
	print_usage(stdout, name);
	printf("\n\t-f, --family\t- Set protocol family to use for"
	       " communicating with HOST. FAMILY can be set to \"inet\""
	       " (IPv4), \"inet6\" (IPv6) or \"unspec\" (automatic).\n");
	printf("\t-4\t\t- Shortcut for --family=inet.\n");
	printf("\t-6\t\t- Shortcut for --family=inet6.\n");
	printf("\t-n, --numeric\t- Avoid name resolution for HOST and PORT.\n");
	printf("\t-H, --host\t- Set hostname, or IP address, to communicate"
	       " with. Defaults to \"%s\".\n", DEFAULT_HOST);
	printf("\t-p, --port\t- Set remote port to use for communicating"
	       " with HOST. Defaults to \"%s\".\n", DEFAULT_PORT);
	printf("\t-t, --timeout\t- Set inactivity timeout.\n");
	printf("\t-P, --password\t- Set password for accessing HOST.\n");
	printf("\t-v, --verbose\t- Verbose output.\n");
	printf("\t-V, --version\t- Display version number and exit.\n");
	printf("\t-h, --help\t- Display this help message and exit.\n");
	printf("\n\tCOMMAND is the accel-ppp command line to be executed");
	printf(" (if omitted, commands are read from standard input).\n");
	printf("\tThe \"help\" command can be used (e.g. \"%s help\") to get"
	       " information about available commands and their syntax.\n",
	       name);
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{.name = "family",
		 .has_arg = required_argument,
		 .flag = NULL,
		 .val = 'f'
		},
		{.name = "numeric",
		 .has_arg = no_argument,
		 .flag = NULL,
		 .val = 'n'
		},
		{.name = "host",
		 .has_arg = required_argument,
		 .flag = NULL,
		 .val = 'H'
		},
		{.name = "port",
		 .has_arg = required_argument,
		 .flag = NULL,
		 .val = 'p'
		},
		{.name = "timeout",
		 .has_arg = required_argument,
		 .flag = NULL,
		 .val = 't'
		},
		{.name = "password",
		 .has_arg = required_argument,
		 .flag = NULL,
		 .val = 'P'
		},
		{.name = "verbose",
		 .has_arg = no_argument,
		 .flag = NULL,
		 .val = 'v'
		},
		{.name = "version",
		 .has_arg = no_argument,
		 .flag = NULL,
		 .val = 'V'
		},
		{.name = "help",
		 .has_arg = no_argument,
		 .flag = NULL,
		 .val = 'h'
		},
		{.name = NULL,
		 .has_arg = 0,
		 .flag = NULL,
		 .val = 0
		}
	};
	struct host_params peer = {
		.str_addr = DEFAULT_HOST,
		.str_port = DEFAULT_PORT,
		.family = AF_UNSPEC,
		.fd = -1
	};
	struct timespec timeout = {
		.tv_sec = 0,
		.tv_nsec = 0
	};
	struct timespec *timeo = NULL;
	struct msghdr *mh = NULL;
	bool numeric = false;
	int inputstream = -1;
	int oindx = 0;
	int ochar;
	int rv;

	while ((ochar = getopt_long(argc, argv, "f:46ni:H:p:t:P:vVh-",
				    long_opts, &oindx)) != -1) {
		if (ochar == '-')
			/* End of options, interpret the following arguments
			   as part of accel-ppp's command */
			break;

		switch (ochar) {
		case 'f':
			if (strcmp(optarg, "inet") == 0)
				peer.family = AF_INET;
			else if (strcmp(optarg, "inet6") == 0)
				peer.family = AF_INET6;
			else if (strcmp(optarg, "unspec") == 0)
				peer.family = AF_UNSPEC;
			else {
				fprintf(stderr, "\"%s\" is not a valid"
					" address family.\n",
					optarg);
				return XSTATUS_BADPARAM;
			}
			break;
		case '4':
			peer.family = AF_INET;
			break;
		case '6':
			peer.family = AF_INET6;
			break;
		case 'n':
			numeric = true;
			break;
		case 'H':
			peer.str_addr = optarg;
			break;
		case 'p':
			peer.str_port = optarg;
			break;
		case 't':
			if (set_timespec(&timeout, optarg) < 0) {
				fprintf(stderr, "\"%s\" is not a valid"
					" timeout value\n", optarg);
				return XSTATUS_BADPARAM;
			}
			break;
		case 'P':
			if (peer.passwd)
				free(peer.passwd);
			peer.passwd = strdup(optarg);
			memset(optarg, '*', strlen(optarg));
			break;
		case 'v':
			verbose = true;
			break;
		case 'V':
			print_version(stdout);
			return EXIT_SUCCESS;
		case 'h':
			print_help(argv[0]);
			return EXIT_SUCCESS;
		default:
			print_usage(stderr, argv[0]);
			return XSTATUS_SYNTAX;
		};
	}

	if (optind < argc || peer.passwd) {
		mh = argv_to_msghdr(argc - optind, argv + optind, peer.passwd);
		if (mh == NULL) {
			rv = XSTATUS_INTERNAL;
			goto out;
		}
	}
	if (optind < argc)
		inputstream = -1;
	else
		inputstream = STDIN_FILENO;

	rv = accel_connect(&peer, numeric);
	if (rv != EXIT_SUCCESS)
		goto out;

	if (timeout.tv_sec == 0 && timeout.tv_nsec == 0)
		timeo = NULL;
	else
		timeo = &timeout;

	rv = accel_talk(inputstream, peer.fd, mh, timeo);

out:
	if (peer.fd >= 0)
		close(peer.fd);
	if (peer.passwd)
		free(peer.passwd);
	if (mh)
		msghdr_free(mh);

	switch (rv) {
	case XSTATUS_CONNFAIL:
		fprintf(stderr, "Connection to \"%s:%s\" failed\n",
			peer.str_addr, peer.str_port);
		break;
	case XSTATUS_TIMEOUT:
		fprintf(stderr, "Timeout expired\n");
		break;
	case XSTATUS_ARGVLEN:
		fprintf(stderr, "Too much data provided on command line."
			" Standard input should be used for transmitting"
			" high amounts of data\n");
		break;
	default:
		/* No generic error message for other exit status */
		break;
	}

	return rv;
}
