#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include "list.h"
#include "l2tp.h"
#include "log.h"
#include "triton.h"

#include "memdebug.h"

struct l2tp_dict_t
{
	struct list_head items;
};

static struct l2tp_dict_t *dict;

#define BUF_SIZE 1024
static char *path, *fname1, *buf;

struct l2tp_dict_attr_t *l2tp_dict_find_attr_by_name(const char *name)
{
	struct l2tp_dict_attr_t *attr;

	list_for_each_entry(attr, &dict->items, entry) {
		if (!strcmp(attr->name, name))
			return attr;
	}

	return NULL;
}

struct l2tp_dict_attr_t *l2tp_dict_find_attr_by_id(int id)
{
	struct l2tp_dict_attr_t *attr;

	list_for_each_entry(attr, &dict->items, entry) {
		if (attr->id == id)
			return attr;
	}

	return NULL;
}

const struct l2tp_dict_value_t *l2tp_dict_find_value(const struct l2tp_dict_attr_t *attr,
						     l2tp_value_t val)
{
	const struct l2tp_dict_value_t *v;

	list_for_each_entry(v, &attr->values, entry) {
		switch (attr->type) {
			case ATTR_TYPE_INT16:
				if (v->val.int16 == val.int16)
					return v;
				break;
			case ATTR_TYPE_INT32:
				if (v->val.int32 == val.int32)
					return v;
				break;
		}
	}

	return NULL;
}

static char *skip_word(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr == ' ' || *ptr == '\t' || *ptr == '\n')
			break;
	return ptr;
}

static char *skip_space(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr != ' ' && *ptr != '\t')
			break;
	return ptr;
}

static int split(char *buf, char **ptr)
{
	int i;

	for (i = 0; i < 6; i++) {
		buf = skip_word(buf);
		if (!*buf)
			return i;

		*buf = 0;

		buf = skip_space(buf + 1);
		if (!*buf)
			return i;

		ptr[i] = buf;
	}

	buf = skip_word(buf);
	//if (*buf == '\n')
		*buf = 0;
	//else if (*buf)
	//	return -1;

	return i;
}


static int dict_load(const char *fname)
{
	FILE *f;
	char *ptr[6], *endptr;
	struct l2tp_dict_attr_t *attr;
	struct l2tp_dict_value_t *value;
	struct list_head *items;
	int i, r, n = 0;

	f = fopen(fname, "r");
	if (!f) {
		log_emerg("l2tp: open '%s': %s\n", fname, strerror(errno));
		return -1;
	}

	items = &dict->items;
	while (fgets(buf, BUF_SIZE, f)) {
		n++;
		if (buf[0] == '#' || buf[0] == '\n' || buf[0] == 0)
			continue;

		r = split(buf, ptr);

		if (!strcmp(buf, "$INCLUDE")) {
			if (r != 1)
				goto out_syntax;

			for (i = strlen(path) - 1; i; i--) {
				if (path[i] == '/') {
					path[i + 1] = 0;
					break;
				}
			}

			strcpy(fname1, path);
			strcat(fname1, ptr[0]);

			if (dict_load(fname1))
				goto out_err;
		} else if (!strcmp(buf, "ATTRIBUTE")) {
			if (r < 3)
				goto out_syntax;

			attr = malloc(sizeof(*attr));
			memset(attr, 0, sizeof(*attr));
			list_add_tail(&attr->entry, items);
			INIT_LIST_HEAD(&attr->values);

			attr->name = strdup(ptr[0]);
			attr->id = strtol(ptr[1], &endptr, 10);
			if (*endptr != 0)
				goto out_syntax;

			if (!strcmp(ptr[2], "none"))
				attr->type = ATTR_TYPE_NONE;
			else if (!strcmp(ptr[2], "int16"))
				attr->type = ATTR_TYPE_INT16;
			else if (!strcmp(ptr[2], "int32"))
				attr->type = ATTR_TYPE_INT32;
			else if (!strcmp(ptr[2], "int64"))
				attr->type = ATTR_TYPE_INT64;
			else if (!strcmp(ptr[2], "octets"))
				attr->type = ATTR_TYPE_OCTETS;
			else if (!strcmp(ptr[2], "string"))
				attr->type = ATTR_TYPE_STRING;
			else
				goto out_syntax;

			attr->M = -1;
			attr->H = -1;

			for (i = 3; i < r; i++) {
				if (!strcmp(ptr[i], "M=0"))
					attr->M = 0;
				else if (!strcmp(ptr[i], "M=1"))
					attr->M = 1;
				else if (!strcmp(ptr[i], "H=0"))
					attr->H = 0;
				else if (!strcmp(ptr[i], "H=1"))
					attr->H = 1;
				else
					goto out_syntax;
			}
		} else if (!strcmp(buf, "VALUE")) {
			if (r != 3)
				goto out_syntax;

			attr = l2tp_dict_find_attr_by_name(ptr[0]);
			if (!attr) {
				log_emerg("l2tp:%s:%i: attribute not found\n", fname, n);
				goto out_err;
			}

			value = malloc(sizeof(*value));
			memset(value, 0, sizeof(*value));
			list_add_tail(&value->entry, &attr->values);

			value->name = strdup(ptr[1]);
			switch (attr->type) {
				case ATTR_TYPE_INT16:
				case ATTR_TYPE_INT32:
					value->val.int16 = strtol(ptr[2], &endptr, 10);
					if (*endptr != 0)
						goto out_syntax;
					break;
				case ATTR_TYPE_STRING:
					value->val.string = strdup(ptr[2]);
					break;
			}
		} else
			goto out_syntax;
	}

	fclose(f);

	return 0;

out_syntax:
	log_emerg("l2tp:%s:%i: syntaxis error\n", fname, n);
out_err:
	fclose(f);
	return -1;
}

static int l2tp_dict_load(const char *fname)
{
	int r;

	dict = _malloc(sizeof(*dict));
	memset(dict, 0, sizeof(*dict));
	INIT_LIST_HEAD(&dict->items);

	path = _malloc(PATH_MAX);
	fname1 = _malloc(PATH_MAX);
	buf = _malloc(BUF_SIZE);

	strcpy(path, fname);

	r = dict_load(fname);

	_free(buf);
	_free(fname1);
	_free(path);

	return r;
}

static void dict_init(void)
{
	const char *opt;

	opt = conf_get_opt("l2tp", "dictionary");
	if (!opt)
		opt = DICTIONARY;

	if (l2tp_dict_load(opt)) {
		log_emerg("l2tp:dict_init:l2tp_dict_load: failed\n");
		_exit(EXIT_FAILURE);
	}
}

DEFINE_INIT(20, dict_init);
