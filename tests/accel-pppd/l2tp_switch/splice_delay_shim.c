/*
 * LD_PRELOAD shim for the splice fd-reuse test: delays a splice() from a pipe
 * into a socket by SPLICE_SHIM_DELAY_MS, so the test can close and reopen the
 * destination fd number while the call is waiting.
 *
 * Only splices whose queued payload contains SPLICE_SHIM_MARKER are delayed;
 * the real splice() then runs with the original arguments.
 *
 * Each delayed call appends two lines to SPLICE_SHIM_LOG with what the fd
 * referred to before and after the delay.
 *
 *   gcc -shared -fPIC -O1 -o splice_delay_shim.so splice_delay_shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Whether `fd_in`'s (pipe) queued data contains the marker, checked with tee()
 * so nothing is consumed. */
static int payload_has_marker(int fd_in, size_t len, const char *marker)
{
	char buf[4096];
	int scratch[2];
	ssize_t n, got = 0;
	int found = 0;

	if (len > sizeof(buf))
		len = sizeof(buf);
	if (pipe(scratch) < 0)
		return 0;

	n = tee(fd_in, scratch[1], len, SPLICE_F_NONBLOCK);
	while (n > 0 && got < n) {
		ssize_t r = read(scratch[0], buf + got, (size_t)(n - got));

		if (r <= 0)
			break;
		got += r;
	}
	if (got > 0)
		found = memmem(buf, (size_t)got, marker, strlen(marker)) != NULL;

	close(scratch[0]);
	close(scratch[1]);
	return found;
}

static void shim_log(const char *what, int fd)
{
	const char *path = getenv("SPLICE_SHIM_LOG");
	char link[PATH_MAX], target[PATH_MAX], line[PATH_MAX * 2];
	ssize_t n;
	int out, len;

	if (!path)
		return;
	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	n = readlink(link, target, sizeof(target) - 1);
	target[n < 0 ? 0 : n] = '\0';
	len = snprintf(line, sizeof(line), "%s fd=%d -> %s\n", what, fd,
		       n < 0 ? "(closed)" : target);
	out = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (out >= 0) {
		ssize_t w = write(out, line, (size_t)len);

		(void)w; /* diagnostics only */
		close(out);
	}
}

ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
	       size_t len, unsigned int flags)
{
	static ssize_t (*real_splice)(int, loff_t *, int, loff_t *, size_t,
				      unsigned int);
	const char *marker = getenv("SPLICE_SHIM_MARKER");
	const char *delay = getenv("SPLICE_SHIM_DELAY_MS");
	struct stat in_st, out_st;

	if (!real_splice)
		real_splice = dlsym(RTLD_NEXT, "splice");

	if (marker && delay && fstat(fd_in, &in_st) == 0 &&
	    S_ISFIFO(in_st.st_mode) && fstat(fd_out, &out_st) == 0 &&
	    S_ISSOCK(out_st.st_mode) &&
	    payload_has_marker(fd_in, len, marker)) {
		long ms = atol(delay);
		struct timespec ts = { .tv_sec = ms / 1000,
				       .tv_nsec = (ms % 1000) * 1000000L };

		shim_log("delay-begin", fd_out);
		nanosleep(&ts, NULL);
		shim_log("delay-end", fd_out);
	}

	return real_splice(fd_in, off_in, fd_out, off_out, len, flags);
}
