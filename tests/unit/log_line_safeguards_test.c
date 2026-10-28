/* A log line assembled from many calls must not outgrow LOG_MAX_SIZE,
 * nor overflow a target buffer once a session header is prepended. */
#include <assert.h>
#include <pthread.h>
#include "triton.h"
#undef DEFINE_INIT
#define DEFINE_INIT(o, f)
#define load_config core_load_config
#include "../../accel-pppd/log.c"
#undef load_config
#include "../../accel-pppd/logs/log_syslog.c"

static char *line;
static int line_len, lines;

mempool_t *mempool_create(int size)
{
	int *p = malloc(sizeof(*p));
	*p = size;
	return (mempool_t *)p;
}
void *mempool_alloc(mempool_t *pool) { return calloc(1, *(int *)pool); }
void mempool_free(void *ptr) { free(ptr); }
char *conf_get_opt(const char *sect, const char *name)
{
	return strcmp(name, "level") ? NULL : "5";
}
int triton_event_register_handler(int ev_id, triton_event_func func) { return 0; }

/* Unpack like the syslog/pgsql targets do, into a buffer of the same size,
 * without a bound of its own so ASan reports an oversized line. */
static void test_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct log_chunk_t *chunk;

	line_len = 0;
	list_for_each_entry(chunk, msg->chunks, entry) {
		memcpy(line + line_len, chunk->msg, chunk->len);
		line_len += chunk->len;
	}
	line[line_len] = 0;
	lines++;
	log_free_msg(msg);
}

static struct log_target_t test_target = {
	.log = test_log,
};

/* the longest line the core passes on, behind the longest session header */
static void test_syslog(void)
{
	struct ap_ctrl ctrl = {};
	struct ap_session ses = {.ctrl = &ctrl};
	struct log_msg_t msg = {};
	struct log_chunk_t *chunk;
	LIST_HEAD(chunks);
	char username[256];
	int i, n = LOG_MAX_SIZE / LOG_CHUNK_SIZE;

	log_buf = malloc(LOG_MAX_SIZE + 1);
	msg.hdr = malloc(sizeof(struct log_chunk_t) + LOG_CHUNK_SIZE + 1);
	assert(log_buf && msg.hdr);
	strcpy(ses.ifname, "ppp0");
	memset(username, 'u', sizeof(username) - 1);
	username[sizeof(username) - 1] = 0;
	ses.username = username;

	for (i = 0; i < n; i++) {
		chunk = malloc(sizeof(*chunk) + LOG_CHUNK_SIZE + 1);
		assert(chunk);
		chunk->len = LOG_CHUNK_SIZE;
		memset(chunk->msg, 'A', LOG_CHUNK_SIZE);
		list_add_tail(&chunk->entry, &chunks);
	}
	chunk->msg[LOG_CHUNK_SIZE - 1] = '\n';
	msg.chunks = &chunks;

	set_hdr(&msg, &ses);
	assert(strlen(msg.hdr->msg) == LOG_CHUNK_SIZE - 1);
	unpack_msg(&msg);
	assert(strlen(log_buf) == LOG_MAX_SIZE);
	assert(!memcmp(log_buf, "ppp0:uuu", 8));
	assert(log_buf[LOG_MAX_SIZE - 1] == 'A');

	/* nothing is written to a buffer that is already full */
	assert(log_unpack_msg(&msg, NULL, 0) == 0);
	assert(log_unpack_msg(&msg, NULL, -LOG_CHUNK_SIZE) == 0);

	/* a short line is unaffected */
	chunk = list_first_entry(&chunks, typeof(*chunk), entry);
	strcpy(chunk->msg, "hello\n");
	chunk->len = 6;
	while (chunks.prev != &chunk->entry) {
		struct log_chunk_t *c = list_entry(chunks.prev, typeof(*c), entry);
		list_del(&c->entry);
		free(c);
	}
	set_hdr(&msg, NULL);
	unpack_msg(&msg);
	assert(!strcmp(log_buf, "hello"));

	list_del(&chunk->entry);
	free(chunk);
	free(msg.hdr);
	free(log_buf);
}

int main(void)
{
	char big[1024], *huge;
	int i;

	line = malloc(LOG_MAX_SIZE + 1);
	assert(line);
	log_init();
	log_register_target(&test_target);
	memset(big, 'A', sizeof(big) - 1);
	big[sizeof(big) - 1] = 0;

	/* the L2TP packet printer: one call per AVP, newline at the end */
	log_info2("recv [");
	for (i = 0; i < 64; i++)
		log_info2(" <%s>", big);
	log_info2("]\n");
	assert(lines == 1);
	assert(line_len == LOG_MAX_SIZE);
	assert(!memcmp(line, "recv [ <AAA", 11));
	assert(line[LOG_MAX_SIZE - 2] == 'A' && line[LOG_MAX_SIZE - 1] == '\n');

	/* the next line starts from scratch */
	log_info2("short");
	log_info2(" line\n");
	assert(lines == 2 && !strcmp(line, "short line\n"));

	/* a line that fits exactly is delivered unchanged */
	for (i = 0; i < 4; i++)
		log_info2("%.1023s", big);
	log_info2("BCD\n");
	assert(lines == 3 && line_len == LOG_MAX_SIZE);
	assert(!strcmp(line + 4 * 1023, "BCD\n"));

	/* an empty format neither ends nor breaks the line */
	log_info2("%s", "");
	log_info2("x\n");
	assert(lines == 4 && !strcmp(line, "x\n"));

	/* a single call longer than LOG_MAX_SIZE still ends its line */
	huge = malloc(2 * LOG_MAX_SIZE);
	assert(huge);
	memset(huge, 'H', 2 * LOG_MAX_SIZE - 1);
	huge[2 * LOG_MAX_SIZE - 1] = 0;
	log_info2("%s\n", huge);
	assert(lines == 5 && line_len == LOG_MAX_SIZE - 1);
	assert(line[LOG_MAX_SIZE - 3] == 'H' && line[LOG_MAX_SIZE - 2] == '\n');
	log_info2("next\n");
	assert(lines == 6 && !strcmp(line, "next\n"));
	free(huge);

	free(line);
	test_syslog();
	puts("Log line safeguards: PASS");
	return 0;
}
