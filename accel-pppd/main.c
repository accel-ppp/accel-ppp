#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include <limits.h>
#include <malloc.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>

#ifdef CRYPTO_OPENSSL
#include <openssl/ssl.h>
#endif

#include "triton/triton.h"

#include "log.h"
#include "events.h"
#include "ap_session.h"
#include "backup.h"
#include "memdebug.h"

#ifndef ARG_MAX
#define ARG_MAX 128*1024
#endif

static char *pid_file;
static char *conf_file;
static char *conf_dump;
static sigset_t orig_set;
static char **argv;
static int argc;
static int restart = -1;
static int term;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

#ifdef CRYPTO_OPENSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
static pthread_mutex_t *ssl_lock_cs;

static unsigned long ssl_thread_id(void)
{
	return (unsigned long)pthread_self();
}

static void ssl_lock(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&ssl_lock_cs[type]);
	else
		pthread_mutex_unlock(&ssl_lock_cs[type]);
}

static void ssl_lock_init(void)
{
	int i;

	ssl_lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&ssl_lock_cs[i], NULL);

	CRYPTO_set_id_callback(ssl_thread_id);
	CRYPTO_set_locking_callback(ssl_lock);
}
#endif

static void openssl_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	ssl_lock_init();
#endif
}
#endif

static void change_limits(void)
{
	FILE *f;
	struct rlimit lim;
	unsigned int nr_open = 1024*1024;

	f = fopen("/proc/sys/fs/nr_open", "r");
	if (f) {
		fscanf(f, "%u", &nr_open);
		fclose(f);
	}

	lim.rlim_cur = nr_open;
	lim.rlim_max = nr_open;
	if (setrlimit(RLIMIT_NOFILE, &lim))
		log_emerg("main: setrlimit: %s\n", strerror(errno));
}

static void config_reload_notify(int r)
{
	if (!r)
		triton_event_fire(EV_CONFIG_RELOAD, NULL);
}

static void config_reload(int num)
{
	triton_conf_reload(config_reload_notify);
}

static void close_all_fd(void)
{
	DIR *dirp;
	struct dirent *ent;
	char path[128];
	int fd, dir_fd;

	sprintf(path, "/proc/%u/fd", getpid());

	dirp = opendir(path);
	if (!dirp)
		return;

	dir_fd = dirfd(dirp);

	while (1) {
		ent = readdir(dirp);
		if (!ent)
			break;

		fd = atol(ent->d_name);
		if (fd > 2 && fd != dir_fd)
			close(fd);
	}

	closedir(dirp);
}

static void __core_restart(int soft)
{
	char exe[PATH_MAX];
	char exe_buf[PATH_MAX];

	pthread_sigmask(SIG_SETMASK, &orig_set, NULL);

#ifdef USE_BACKUP
	if (soft)
		backup_restore_fd();
	else
#endif
		close_all_fd();

	sprintf(exe, "/proc/%u/exe", getpid());
	readlink(exe, exe_buf, PATH_MAX);

	while (1) {
		execv(exe, argv);
		sleep(3);
	}
}

void core_restart(int soft)
{
#ifdef USE_BACKUP
	if (soft)
		__core_restart(1);
#endif
	restart = soft;
	kill(getpid(), SIGTERM);
}

static void sigsegv(int num)
{
	char cmd[128];
	char dump[128];
	char exec_file[PATH_MAX];
	char exec_file_buf[PATH_MAX];
	pid_t pid;
	FILE *f;
	int fd;
	char pid_str[16];
	unsigned int t;

	pthread_sigmask(SIG_SETMASK, &orig_set, NULL);

	if (conf_dump) {
		t = time(NULL);
		sprintf(pid_str, "%u", getpid());
		sprintf(cmd, "cmd-%u", t);
		chdir(conf_dump);

		pid = fork();
		if (pid == 0) {
		printf("starting gdb...\n");
		sprintf(dump, "dump-%u", t);
		fd = open(dump, O_CREAT|O_TRUNC|O_WRONLY,0600);
		if (fd == -1) {
			log_emerg("main: sigsegv: open failed: %s\n", strerror(errno));
			_exit(0);
		}

		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);

		f = fopen(cmd, "w");
		if (!f) {
			log_emerg("main: sigsegv: open failed: %s\n", strerror(errno));
			_exit(0);
		}
		fprintf(f, "info shared\nthread apply all bt full\ngenerate-core-file core-%u\ndetach\nquit\n", t);
		fclose(f);

		sprintf(exec_file, "/proc/%s/exe", pid_str);
		readlink(exec_file, exec_file_buf, PATH_MAX);

		execlp("gdb", "gdb", "-x", cmd, exec_file, pid_str, NULL);
		perror("exec");
		_exit(0);
		}

		printf("waitpid: %i\n", waitpid(pid, NULL, 0));

		unlink(cmd);
	}

	__core_restart(1);
}

static void shutdown_cb()
{
	pthread_mutex_lock(&lock);
	term = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
}

static void log_version()
{
	log_msg("accel-ppp version %s\n", ACCEL_PPP_VERSION);
}

enum {
	OPT_DUMP = CHAR_MAX + 1,
	OPT_INTERNAL,
	OPT_NO_SIGSEGV,
	OPT_NO_SIGINT,
};

static const struct option long_opts[] = {
	{ "config",     required_argument, NULL, 'c'            },
	{ "pid",        required_argument, NULL, 'p'            },
	{ "daemon",     no_argument,       NULL, 'd'            },
	{ "dump",       required_argument, NULL, OPT_DUMP       },
	{ "internal",   no_argument,       NULL, OPT_INTERNAL   },
	{ "no-sigsegv", no_argument,       NULL, OPT_NO_SIGSEGV },
	{ "no-sigint",  no_argument,       NULL, OPT_NO_SIGINT  },
	{ "version",    no_argument,       NULL, 'V'            },
	{ "help",       no_argument,       NULL, 'h'            },
	{ NULL,         0,                 NULL, 0              }
};

static void print_version(FILE *stream)
{
	fprintf(stream, "accel-ppp %s\n", ACCEL_PPP_VERSION);
}

static void print_usage(FILE *stream)
{
	fprintf(stream, "Usage:\t%s -c CONFIG [-p PID] [-d]\n", "accel-pppd");
}

static void print_help(FILE *stream)
{
	print_usage(stream);
	fprintf(stream, "\n"
		"\t-с, --config\t- Read config from CONFIG file \n"
		"\t-p, --pid\t- Write pid to PID file\n"
		"\t-d, --daemon\t- Daemon mode\n"
		"\t-V, --version\t- Show version and exit\n"
		"\t-h, --help\t- Show help and exit\n");
}

int main(int _argc, char **_argv)
{
	sigset_t set;
	int c, sig, goto_daemon = 0, len;
	pid_t pid = 0;
	struct sigaction sa;
	int pagesize = sysconf(_SC_PAGESIZE);
	char *dump = NULL;
	int internal = 0;
	int no_sigint = 0;
	int no_sigsegv = 0;

	argc = _argc;
	argv = _argv;
	if (argc < 2)
		goto usage;

	while ((c = getopt_long(argc, argv, "c:p:dVh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			conf_file = optarg;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'd':
			goto_daemon = 1;
			break;
		case OPT_DUMP:
			dump = optarg;
			break;
		case OPT_INTERNAL:
			internal = 1;
			break;
		case OPT_NO_SIGSEGV:
			no_sigsegv = 1;
			break;
		case OPT_NO_SIGINT:
			no_sigint = 1;
			break;
		case 'V':
			print_version(stdout);
			return EXIT_SUCCESS;
		case 'h':
			print_help(stdout);
			return EXIT_SUCCESS;
		default:
			goto usage;
		}
	}

	if (!conf_file)
		goto usage;

	if (dump) {
		len = (strlen(dump) / pagesize + 1) * pagesize;
		conf_dump = memalign(pagesize, len);
		strcpy(conf_dump, dump);
		mprotect(conf_dump, len, PROT_READ);
	}

	if (internal) {
		while (getppid() != 1)
			sleep(1);
	}

	srandom(time(NULL));

	if (triton_init(conf_file)) {
		log_emerg("main: triton_init: conf_file failed\n");
		_exit(EXIT_FAILURE);
	}

	if (goto_daemon && pid != getpid()) {
		/*pid_t pid = fork();
		if (pid > 0)
			_exit(EXIT_SUCCESS);
		if (pid < 0) {
			perror("fork");
			return EXIT_FAILURE;
		}
		if (setsid() < 0)
			_exit(EXIT_FAILURE);
		pid = fork();
		if (pid)
			_exit(0);
		umask(0);
		chdir("/");
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);*/
		daemon(0, 0);
	}

	if (pid_file) {
		FILE *f = fopen(pid_file, "w");
		if (f) {
			fprintf(f, "%i", getpid());
			fclose(f);
		}
	}

	change_limits();

#ifdef CRYPTO_OPENSSL
	openssl_init();
#endif

	triton_register_init(0, log_version);

	if (triton_load_modules("modules")) {
		log_emerg("main: triton_load_modules: failed\n");
		return EXIT_FAILURE;
	}

	triton_run();

	sigfillset(&set);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = config_reload;
	sa.sa_mask = set;
	sigaction(SIGUSR1, &sa, NULL);

	if (!no_sigsegv) {
		sa.sa_handler = sigsegv;
		sa.sa_mask = set;
		sigaction(SIGSEGV, &sa, NULL);
	}


	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGBUS);
	sigdelset(&set, SIGHUP);
	sigdelset(&set, SIGIO);
	sigdelset(&set, SIGUSR1);
	sigdelset(&set, 35);
	sigdelset(&set, 36);
	if (no_sigint)
		sigdelset(&set, SIGINT);
	pthread_sigmask(SIG_SETMASK, &set, &orig_set);

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	if (!no_sigint)
		sigaddset(&set, SIGINT);

#ifdef USE_BACKUP
	backup_restore(internal);
#endif

	sigwait(&set, &sig);
	log_info1("terminate, sig = %i\n", sig);

	ap_shutdown_soft(shutdown_cb, 1);

	pthread_mutex_lock(&lock);
	while (!term)
		pthread_cond_wait(&cond, &lock);
	pthread_mutex_unlock(&lock);

	triton_terminate();

	if (restart != -1)
		__core_restart(restart);

	if (pid_file)
		unlink(pid_file);

	return EXIT_SUCCESS;

usage:
	print_help(stderr);
	_exit(EXIT_FAILURE);
}
