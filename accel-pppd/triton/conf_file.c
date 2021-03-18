#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "triton_p.h"

#include "memdebug.h"

struct sect_t {
	struct list_head entry;

	struct conf_sect_t *sect;
};

struct conf_ctx {
	const char *fname;
	FILE *file;
	int line;
	struct list_head *items;
};

static LIST_HEAD(sections);
static char *conf_fname;

static char* skip_space(char *str);
static char* skip_word(char *str);

static struct conf_sect_t *find_sect(const char *name);
static struct conf_sect_t *create_sect(const char *name);
static int sect_add_item(struct conf_ctx *ctx, const char *name, char *val, char *raw);
static struct conf_option_t *find_item(struct conf_sect_t *, const char *name);
static int load_file(struct conf_ctx *ctx);

static int __conf_load(struct conf_ctx *ctx, const char *fname)
{
	struct conf_ctx ctx1;
	int r;

	ctx1.fname = fname;
	ctx1.file = fopen(fname, "r");
	ctx1.line = 0;
	ctx1.items = ctx->items;
	if (!ctx1.file) {
		perror("conf_file:open");
		return -1;
	}

	r = load_file(&ctx1);

	fclose(ctx1.file);

	return r;
}

static int load_file(struct conf_ctx *ctx)
{
	char *str2;
	char buf[1024] = {0};

	static struct conf_sect_t *cur_sect = NULL;

	while(1) {
		int len;
		char *str, *raw;

		if (!fgets(buf, 1024, ctx->file))
			break;
		ctx->line++;

		len = strlen(buf);
		if (len && buf[len - 1] == '\n')
			buf[--len] = 0;

		while (len && (buf[len - 1] == ' ' || buf[len - 1] == '\t'))
			buf[--len] = 0;

		str = skip_space(buf);
		if (*str == '#' || *str == 0)
			continue;

		if (strncmp(str, "$include", 8) == 0)	{
			str = skip_word(str);
			str = skip_space(str);
			if (__conf_load(ctx, str))
				break;
			continue;
		}

		if (*str == '[') {
			for (str2 = ++str; *str2 && *str2 != ']'; str2++);
			if (*str2 != ']') {
				fprintf(stderr, "conf_file:%s:%i: sintax error\n", ctx->fname, ctx->line);
				return -1;
			}

			cur_sect = find_sect(str);

			if (cur_sect && ctx->items != &cur_sect->items) {
				fprintf(stderr, "conf_file:%s:%i: cann't open section inside option\n", ctx->fname, ctx->line);
				return -1;
			}

			*str2 = 0;
			if (!cur_sect)
				cur_sect = create_sect(str);
			ctx->items = &cur_sect->items;
			continue;
		}

		if (!cur_sect) {
			fprintf(stderr, "conf_file:%s:%i: no section opened\n", ctx->fname, ctx->line);
			return -1;
		}

		if (*str == '}' && ctx->items != &cur_sect->items)
			return 0;

		raw = _strdup(str);
		str2 = skip_word(str);
		if (*str2 == ' ') {
			*str2 = 0;
			++str2;
		}

		str2 = skip_space(str2);
		if (*str2 == '=' || *str2 == ',') {
			*str2 = 0;
			str2 = skip_space(str2 + 1);
			if (*str2 && *(str2 + 1) && *str2 == '$' && *(str2 + 1) == '{') {
				char *s;
				struct conf_option_t *opt;
				for (s = str2+2; *s && *s != '}'; s++);
				if (*s == '}') {
					*s = 0;
					str2 += 2;
				}
				opt = find_item(cur_sect, str2);
				if (!opt) {
					fprintf(stderr, "conf_file:%s:%i: parent option not found\n", ctx->fname, ctx->line);
					_free(raw);
					return -1;
				}
				str2 = opt->val;
			}
		} else
			str2 = NULL;
		if (sect_add_item(ctx, str, str2, raw))
			return -1;
	}

	return 0;
}

/*static void print_items(struct list_head *items, int dep)
{
	struct conf_option_t *opt;
	int i;

	list_for_each_entry(opt, items, entry) {
		for (i = 0; i < dep; i++)
			printf("\t");
		printf("%s=%s\n", opt->name, opt->val);
		print_items(&opt->items, dep + 1);
	}
}

static void print_conf()
{
	struct sect_t *s;

	list_for_each_entry(s, &sections, entry) {
		printf("[%s]\n", s->sect->name);
		print_items(&s->sect->items, 0);
	}
}*/

int conf_load(const char *fname)
{
	int r;
	struct conf_ctx ctx;

	if (fname) {
		if (conf_fname)
			_free(conf_fname);
		conf_fname = _strdup(fname);
	} else
		fname = conf_fname;

	ctx.items = NULL;
	r = __conf_load(&ctx, fname);

	return r;
}

static void free_items(struct list_head *items)
{
	struct conf_option_t *opt;

	while (!list_empty(items)) {
		opt = list_entry(items->next, typeof(*opt), entry);
		list_del(&opt->entry);
		if (opt->val)
			_free(opt->val);
		_free(opt->name);
		_free(opt->raw);
		free_items(&opt->items);
		_free(opt);
	}
}

int conf_reload(const char *fname)
{
	struct sect_t *sect;
	int r;
	LIST_HEAD(sections_bak);

	list_splice_init(&sections, &sections_bak);

	r = conf_load(fname);

	if (r)
		list_splice(&sections_bak, &sections);
	else {
		while (!list_empty(&sections_bak)) {
			sect = list_entry(sections_bak.next, typeof(*sect), entry);
			list_del(&sect->entry);
			free_items(&sect->sect->items);
			_free((char *)sect->sect->name);
			_free(sect->sect);
			_free(sect);
		}
	}

	return r;
}

static char* skip_space(char *str)
{
	for (; *str && (*str == ' ' || *str == '\t'); str++);
	return str;
}
static char* skip_word(char *str)
{
	for (; *str && (*str != ' ' && *str != '\t' && *str != '='); str++);
	return str;
}

static struct conf_sect_t *find_sect(const char *name)
{
	struct sect_t *s;
	list_for_each_entry(s, &sections, entry)
		if (strcmp(s->sect->name, name) == 0) return s->sect;
	return NULL;
}

static struct conf_sect_t *create_sect(const char *name)
{
	struct sect_t *s = _malloc(sizeof(struct sect_t));

	s->sect = _malloc(sizeof(struct conf_sect_t));
	s->sect->name = (char*)_strdup(name);
	INIT_LIST_HEAD(&s->sect->items);

	list_add_tail(&s->entry, &sections);

	return s->sect;
}

static int sect_add_item(struct conf_ctx *ctx, const char *name, char *val, char *raw)
{
	struct conf_option_t *opt = _malloc(sizeof(struct conf_option_t));
	int r = 0;
	int len = 0;

	if (val) {
		len = strlen(val);
		if (val[len - 1] == '{') {
			val[len - 1] = 0;
			while (len && (val[len - 1] == ' ' || val[len - 1] == '\t'))
				len--;
			len = 1;
		}
		else
			len = 0;
	}

	opt->name = _strdup(name);
	opt->val = val ? _strdup(val) : NULL;
	opt->raw = raw;
	INIT_LIST_HEAD(&opt->items);

	list_add_tail(&opt->entry, ctx->items);

	if (len) {
		struct list_head *items = ctx->items;
		ctx->items = &opt->items;
		r = load_file(ctx);
		ctx->items = items;
	}

	return r;
}

static struct conf_option_t *find_item(struct conf_sect_t *sect, const char *name)
{
	struct conf_option_t *opt;
	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, name) == 0)
			return opt;
	}

	return NULL;
}

__export struct conf_sect_t * conf_get_section(const char *name)
{
	return find_sect(name);
}

__export char * conf_get_opt(const char *sect, const char *name)
{
	struct conf_option_t *opt;
	struct conf_sect_t *s = conf_get_section(sect);

	if (!s)
		return NULL;

	opt = find_item(s, name);
	if (!opt)
		return NULL;

	return opt->val;
}

