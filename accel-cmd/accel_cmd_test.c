/* Exercise the production timeout parser without opening a connection. */
#define main accel_cmd_main
#include "accel_cmd.c"
#undef main

int main(void)
{
	static const struct {
		const char *value;
		time_t seconds;
		long nanoseconds;
	} cases[] = {
		{ "0", 0, 0 },
		{ "2s", 2, 0 },
		{ "0ms", 0, 0 },
		{ "1ms", 0, 1000000 },
		{ "500ms", 0, 500000000 },
		{ "999ms", 0, 999000000 },
		{ "1000ms", 1, 0 },
		{ "1001ms", 1, 1000000 },
		{ "1500ms", 1, 500000000 },
		{ "1us", 0, 1000 },
		{ "1500000us", 1, 500000000 },
	};
	static const char *invalid[] = { "", "-1ms", "1.5ms", "1m" };
	struct timespec timeout;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (set_timespec(&timeout, cases[i].value) ||
		    timeout.tv_sec != cases[i].seconds ||
		    timeout.tv_nsec != cases[i].nanoseconds) {
			fprintf(stderr, "incorrect timeout for %s\n", cases[i].value);
			return 1;
		}
	}
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		if (!set_timespec(&timeout, invalid[i])) {
			fprintf(stderr, "accepted invalid timeout %s\n", invalid[i]);
			return 1;
		}
	}

	puts("accel-cmd timeout parsing: PASS");
	return 0;
}
