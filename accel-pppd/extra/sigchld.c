#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "triton.h"
#include "spinlock.h"
#include "log.h"

#include "sigchld.h"

#include "memdebug.h"

static LIST_HEAD(handlers);
static int lock_refs;
static pthread_mutex_t handlers_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t refs_cond = PTHREAD_COND_INITIALIZER;
static pthread_t sigchld_thr;

static void* sigchld_thread(void *arg)
{
	sigset_t set;
	struct sigchld_handler_t *h, *h0;
	pid_t pid;
	int status, sig;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigaddset(&set, SIGQUIT);

	while (1) {
		pid = waitpid(-1, &status, 0);
		if (pid < 0) {
			if (errno == EINTR)
				continue;
			if (errno == ECHILD) {
				sigwait(&set, &sig);
				if (sig == SIGQUIT)
					break;
				continue;
			}
			log_error("sigchld: waitpid: %s\n", strerror(errno));
			continue;
		}

		pthread_mutex_lock(&handlers_lock);
		while (lock_refs)
			pthread_cond_wait(&refs_cond, &handlers_lock);

		h0 = NULL;
		list_for_each_entry(h, &handlers, entry) {
			if (h->pid == pid) {
				h0 = h;
				list_del(&h0->entry);
				pthread_mutex_lock(&h0->lock);
				break;
			}
		}
		pthread_mutex_unlock(&handlers_lock);
		if (h0) {
			if (WIFEXITED(status))
				h0->handler(h0, WEXITSTATUS(status));
			else if (WIFSIGNALED(status))
				h0->handler(h0, 128 + WTERMSIG(status));
			else
				h0->handler(h0, -1);
			h0->pid = 0;
			pthread_mutex_unlock(&h0->lock);
		}
	}

	return NULL;
}

void __export sigchld_register_handler(struct sigchld_handler_t *h)
{
	pthread_mutex_init(&h->lock, NULL);

	pthread_mutex_lock(&handlers_lock);
	list_add_tail(&h->entry, &handlers);
	pthread_mutex_unlock(&handlers_lock);
}

int __export sigchld_unregister_handler(struct sigchld_handler_t *h)
{
	int r = 0;

	pthread_mutex_lock(&handlers_lock);
	pthread_mutex_lock(&h->lock);
	if (h->pid) {
		list_del(&h->entry);
		h->pid = 0;
		r = 1;
	}
	pthread_mutex_unlock(&h->lock);
	pthread_mutex_unlock(&handlers_lock);

	return r;
}

void __export sigchld_lock()
{
	pthread_mutex_lock(&handlers_lock);
	++lock_refs;
	pthread_mutex_unlock(&handlers_lock);
}

void __export sigchld_unlock()
{
	pthread_mutex_lock(&handlers_lock);
	if (--lock_refs == 0)
		pthread_cond_signal(&refs_cond);
	pthread_mutex_unlock(&handlers_lock);
}

static void __init init(void)
{
	if (pthread_create(&sigchld_thr, NULL, sigchld_thread, NULL))
		log_emerg("sigchld: pthread_create: %s\n", strerror(errno));
}

