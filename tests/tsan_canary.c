/*
 * Proves tests/tsan.supp can still fail a run: two threads, entered through a
 * function named triton_thread like the daemon's workers, race on an int. The
 * racing access itself is in worker(), so only a "race:triton_thread" entry
 * (which matches any frame) would hide it; "race_top:" must not.
 *
 * CI builds it with -fsanitize=thread and runs it with
 * TSAN_OPTIONS=exitcode=66:suppressions=tests/tsan.supp, expecting status 66.
 */
#include <pthread.h>
#include <stddef.h>

static int shared;

static void worker(void)
{
	for (int i = 0; i < 100000; i++)
		shared++;
}

void *triton_thread(void *arg)
{
	(void)arg;
	worker();
	return NULL;
}

int main(void)
{
	pthread_t a, b;

	pthread_create(&a, NULL, triton_thread, NULL);
	pthread_create(&b, NULL, triton_thread, NULL);
	pthread_join(a, NULL);
	pthread_join(b, NULL);
	return 0;
}
