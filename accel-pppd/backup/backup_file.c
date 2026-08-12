#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include <openssl/md5.h>

#include "triton.h"
#include "log.h"
#include "ap_session.h"
#include "backup.h"
#include "memdebug.h"

#define VERSION 1

struct fs_backup_data
{
	struct list_head fd_list;
	int fd;
	void *map_addr;
	int map_len;
	char sessionid[AP_SESSIONID_LEN];
	struct backup_data data;
};

static char *conf_path;

static struct backup_storage file_storage;

static struct backup_data *fs_create(struct ap_session *ses)
{
	struct fs_backup_data *d = _malloc(sizeof(*d));

	if (!d)
		return NULL;

	memset(d, 0, sizeof(*d));
	d->fd = -1;
	INIT_LIST_HEAD(&d->fd_list);
	INIT_LIST_HEAD(&d->data.mod_list);
	d->data.ses = ses;
	d->data.storage = &file_storage;

	return &d->data;
}

static int fs_commit(struct backup_data *d)
{
	char fname[PATH_MAX];
	int fd;
	struct backup_mod *mod;
	struct backup_tag *tag;
	struct iovec iov[IOV_MAX];
	int i, len, n;
	MD5_CTX md5;
	unsigned char md5_buf[16];
	uint8_t end[4] = {0, 0, 0, 0};
	uint8_t version = VERSION;
	uint8_t *ptr;

	if (!conf_path)
		return -1;

	sprintf(fname, "%s/%s", conf_path, d->ses->sessionid);

	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE);

	if (fd < 0) {
		log_error("backup: can not create file '%s': %s\n", fname, strerror(errno));
		return -1;
	}

	MD5_Init(&md5);
	MD5_Update(&md5, &version, 1);

	iov[0].iov_base = &version;
	iov[0].iov_len = 1;
	i = 1;
	len = 1;

	list_for_each_entry(mod, &d->mod_list, entry) {
		MD5_Update(&md5, &mod->id, 1);
		iov[i].iov_base = &mod->id;
		iov[i].iov_len = 1;
		i++;
		len++;

		list_for_each_entry(tag, &mod->tag_list, entry) {
			ptr = (uint8_t *)(tag + 1);
			*ptr = tag->id; ptr++;
			*ptr = tag->internal ? 1 : 0; ptr++;
			*(uint16_t *)ptr = tag->size;
			MD5_Update(&md5, tag + 1, 4 + tag->size);
			iov[i].iov_base = tag + 1;
			iov[i].iov_len = 4 + tag->size;
			i++;
			len += 4 + tag->size;
			if (i == IOV_MAX - 2) {
				n = writev(fd, iov, i);
				if (n < len) {
					log_error("backup: short write %i/%i\n", n, len);
					goto out_err;
				}
				i = 0;
				len = 0;
			}
		}

		MD5_Update(&md5, end, 4);
		iov[i].iov_base = end;
		iov[i].iov_len = 4;
		i++;
		len += 4;
	}

	MD5_Final(md5_buf, &md5);

	iov[i].iov_base = md5_buf;
	iov[i].iov_len = 16;
	len += 16;

	n = writev(fd, iov, i + 1);
	if (n < len) {
		log_error("backup: short write %i/%i\n", n, len);
		goto out_err;
	}

	close(fd);

	while (!list_empty(&d->mod_list)) {
		mod = list_entry(d->mod_list.next, typeof(*mod), entry);
		list_del(&mod->entry);
		while (!list_empty(&mod->tag_list)) {
			tag = list_entry(mod->tag_list.next, typeof(*tag), entry);
			list_del(&tag->entry);
			_free(tag);
		}
		_free(mod);
	}

	return 0;

out_err:
	close(fd);
	unlink(fname);
	return -1;
}

static void fs_free(struct backup_data *d)
{
	struct fs_backup_data *fsd = container_of(d, typeof(*fsd), data);
	char fname[PATH_MAX];

	if (fsd->map_addr)
		munmap(fsd->map_addr, fsd->map_len);

	if (fsd->fd != -1)
		close(fsd->fd);

	sprintf(fname, "%s/%s", conf_path, d->ses->sessionid);
	unlink(fname);

	_free(fsd);
}

static struct backup_mod *fs_alloc_mod(struct backup_data *d)
{
	struct backup_mod *m = _malloc(sizeof(struct backup_mod));

	if (!m)
		return NULL;

	memset(m, 0, sizeof(*m));
	INIT_LIST_HEAD(&m->tag_list);

	return m;
}

static void fs_free_mod(struct backup_mod *mod)
{
	_free(mod);
}

static struct backup_tag *fs_alloc_tag(struct backup_data *d, int size)
{
	struct backup_tag *t = _malloc(sizeof(struct backup_tag) + 4 + size);

	if (!t)
		return NULL;

	memset(t, 0, sizeof(*t));

	t->data = (uint8_t *)(t + 1) + 4;

	return t;
}

static void fs_free_tag(struct backup_data *d, struct backup_tag *tag)
{
	_free(tag);
}

static void fs_add_fd(struct backup_data *d, int fd)
{

}

static void restore_session(const char *fn, int internal)
{
	char fname[PATH_MAX];
	int fd;
	struct stat st;
	uint8_t *ptr, *endptr;
	MD5_CTX md5;
	unsigned char md5_buf[16];
	struct backup_data *d;
	struct fs_backup_data *fsd;
	struct backup_mod *mod;
	struct backup_tag *tag;

	sprintf(fname, "%s/%s", conf_path, fn);

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		log_emerg("backup_file: open '%s': %s\n", fname, strerror(errno));
		return;
	}

	fstat(fd, &st);

	ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		log_emerg("backup_file: mmap '%s': %s\n", fname, strerror(errno));
		close(fd);
		return;
	}

	if (*ptr != VERSION)
		goto out;

	MD5_Init(&md5);
	MD5_Update(&md5, ptr, st.st_size - 16);
	MD5_Final(md5_buf, &md5);

	if (memcmp(md5_buf, ptr + st.st_size - 16, 16))
		goto out;

	d = fs_create(NULL);
	if (!d)
		goto out;

	d->internal = internal;

	fsd = container_of(d, typeof(*fsd), data);
	fsd->fd = fd;
	fsd->map_addr = ptr;
	fsd->map_len = st.st_size;

	endptr = ptr + st.st_size - 16;
	ptr++;

	while (ptr < endptr) {
		mod = fs_alloc_mod(d);
		list_add_tail(&mod->entry, &d->mod_list);
		mod->data = d;
		mod->id = *ptr; ptr++;
		while (ptr < endptr) {
			if (*(uint8_t *)ptr == 0) {
				ptr += 4;
				break;
			}

			if (!internal && ptr[1]) {
				ptr += 4 + *(uint16_t *)(ptr + 2);
				continue;
			}

			tag = fs_alloc_tag(d, 0);
			tag->id = *ptr; ptr++;
			tag->internal = (*ptr & 0x01) ? 1 : 0; ptr ++;
			tag->size = *(uint16_t *)ptr; ptr += 2;
			tag->data = ptr; ptr += tag->size;

			list_add_tail(&tag->entry, &mod->tag_list);
		}
	}

	backup_restore_session(d);

	return;

out:
	munmap(ptr, st.st_size);
	close(fd);
}

static void fs_restore(int internal)
{
	DIR *dirp;
	struct dirent ent, *res;

	if (!conf_path)
		return;

	dirp = opendir(conf_path);
	if (!dirp) {
		log_emerg("backup_file: opendir: %s\n", strerror(errno));
		return;
	}

	while (1) {
		if (readdir_r(dirp, &ent, &res)) {
			log_emerg("backup_file: readdir: %s\n", strerror(errno));
			break;
		}
		if (!res)
			break;
		if (strcmp(ent.d_name, ".") == 0 || strcmp(ent.d_name, "..") == 0)
			continue;
		restore_session(ent.d_name, internal);
	}

	closedir(dirp);
}

static struct backup_storage file_storage = {
	.create = fs_create,
	.commit = fs_commit,
	.free = fs_free,
	.alloc_mod = fs_alloc_mod,
	.free_mod = fs_free_mod,
	.add_fd = fs_add_fd,
	.alloc_tag = fs_alloc_tag,
	.free_tag = fs_free_tag,
	.restore = fs_restore,
};

static void init(void)
{
	conf_path = conf_get_opt("backup", "path");

	backup_register_storage(&file_storage);
}

DEFINE_INIT(1000, init);
