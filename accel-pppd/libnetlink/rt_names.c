/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * rt_names.c		rtnetlink names DB.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <dirent.h>
#include <limits.h>

#include <asm/types.h>
#include <linux/rtnetlink.h>

#include "rt_names.h"
#include "utils.h"

#define NAME_MAX_LEN 512
#define CONFDIR "/etc/iproute2"

int numeric;

struct rtnl_hash_entry {
	struct rtnl_hash_entry	*next;
	const char		*name;
	unsigned int		id;
};

static int fread_id_name(FILE *fp, int *id, char *namebuf)
{
	char buf[NAME_MAX_LEN];

	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;

		while (*p == ' ' || *p == '\t')
			p++;

		if (*p == '#' || *p == '\n' || *p == 0)
			continue;

		if (sscanf(p, "0x%x %s\n", id, namebuf) != 2 &&
				sscanf(p, "0x%x %s #", id, namebuf) != 2 &&
				sscanf(p, "%d %s\n", id, namebuf) != 2 &&
				sscanf(p, "%d %s #", id, namebuf) != 2) {
			strcpy(namebuf, p);
			return -1;
		}
		return 1;
	}
	return 0;
}

static int
rtnl_hash_initialize(const char *file, struct rtnl_hash_entry **hash, int size)
{
	struct rtnl_hash_entry *entry;
	FILE *fp;
	int id;
	char namebuf[NAME_MAX_LEN] = {0};
	int ret;

	fp = fopen(file, "r");
	if (!fp)
		return -1;

	while ((ret = fread_id_name(fp, &id, &namebuf[0]))) {
		if (ret == -1) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
					file, namebuf);
			fclose(fp);
			return -1;
		}

		if (id < 0)
			continue;

		entry = malloc(sizeof(*entry));
		if (entry == NULL) {
			fprintf(stderr, "malloc error: for entry\n");
			break;
		}
		entry->id   = id;
		entry->name = strdup(namebuf);
		entry->next = hash[id & (size - 1)];
		hash[id & (size - 1)] = entry;
	}
	fclose(fp);
}

static struct rtnl_hash_entry dflt_table_entry  = { .name = "default" };
static struct rtnl_hash_entry main_table_entry  = { .name = "main" };
static struct rtnl_hash_entry local_table_entry = { .name = "local" };

static struct rtnl_hash_entry *rtnl_rttable_hash[256] = {
	[RT_TABLE_DEFAULT] = &dflt_table_entry,
	[RT_TABLE_MAIN]    = &main_table_entry,
	[RT_TABLE_LOCAL]   = &local_table_entry,
};

static int rtnl_rttable_init;

static int rtnl_rttable_initialize(void)
{
	struct dirent *de;
	DIR *d;
	int i;

	rtnl_rttable_init = 1;
	for (i = 0; i < 256; i++) {
		if (rtnl_rttable_hash[i])
			rtnl_rttable_hash[i]->id = i;
	}
	rtnl_hash_initialize(CONFDIR "/rt_tables",
			     rtnl_rttable_hash, 256);

	d = opendir(CONFDIR "/rt_tables.d");
	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		size_t len;

		if (*de->d_name == '.')
			continue;

		/* only consider filenames ending in '.conf' */
		len = strlen(de->d_name);
		if (len <= 5)
			continue;
		if (strncmp(de->d_name + len - 5, ".conf", strlen(".conf")))
			continue;

		snprintf(path, sizeof(path),
			 CONFDIR "/rt_tables.d/%s", de->d_name);
		rtnl_hash_initialize(path, rtnl_rttable_hash, 256);
	}
	closedir(d);
}

const char *rtnl_rttable_n2a(__u32 id, char *buf, int len)
{
	struct rtnl_hash_entry *entry;

	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();
	entry = rtnl_rttable_hash[id & 255];
	while (entry && entry->id != id)
		entry = entry->next;
	if (!numeric && entry)
		return entry->name;
	snprintf(buf, len, "%u", id);
	return buf;
}

int rtnl_rttable_a2n(__u32 *id, const char *arg)
{
	static const char *cache;
	static unsigned long res;
	struct rtnl_hash_entry *entry;
	char *end;
	unsigned long i;

	if (cache && strncmp(cache, arg, strlen(arg)) == 0) {
		*id = res;
		return 0;
	}

	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();

	for (i = 0; i < 256; i++) {
		entry = rtnl_rttable_hash[i];
		while (entry && strncmp(entry->name, arg, strlen(arg)))
			entry = entry->next;
		if (entry) {
			cache = entry->name;
			res = entry->id;
			*id = res;
			return 0;
		}
	}

	i = strtoul(arg, &end, 0);
	if (!end || end == arg || *end || i > RT_TABLE_MAX)
		return -1;
	*id = i;
	return 0;
}
