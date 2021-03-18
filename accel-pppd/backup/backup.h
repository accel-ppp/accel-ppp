#ifndef __BACKUP_H
#define __BACKUP_H

#include <stdint.h>
#include <sys/types.h>

#include "ap_session.h"
#include "list.h"

#define MODID_COMMON  1
#define MODID_RADIUS  2
#define MODID_PPPOE   3
#define MODID_IPOE    4
#define MODID_PPTP    5
#define MODID_L2TP    6
#define MODID_IPPOOL  7

struct backup_storage;
struct backup_data;

struct backup_tag
{
	struct list_head entry;
	uint16_t internal:1;
	uint16_t id:15;
	uint16_t size;
	uint8_t *data;
};

struct backup_mod
{
	struct backup_data *data;
	struct list_head entry;
	int id;
	struct list_head tag_list;
};

struct backup_data
{
	struct ap_session *ses;
	struct backup_storage *storage;
	struct list_head mod_list;
	unsigned int internal:1;
};

struct backup_module
{
	struct list_head entry;
	int id;

	int (*save)(struct ap_session *, struct backup_mod *);
	int (*restore)(struct ap_session *, struct backup_mod *);

	struct ap_session *(*ctrl_restore)(struct backup_mod *);
	void (*ctrl_start)(struct ap_session *ses);
	void (*restore_complete)(void);
};

struct backup_storage
{
	struct list_head entry;

	/*int (*check_integrity)(void);
	int (*restore)(int internal);*/

	void (*restore)(int internal);

	struct backup_data *(*create)(struct ap_session *);
	int (*commit)(struct backup_data *);
	void (*free)(struct backup_data *);

	struct backup_mod *(*alloc_mod)(struct backup_data *);
	void (*free_mod)(struct backup_mod *);

	void (*add_fd)(struct backup_data *, int fd);

	struct backup_tag *(*alloc_tag)(struct backup_data *, int size);
	void (*free_tag)(struct backup_data *, struct backup_tag *);
};

void backup_register_module(struct backup_module *);
void backup_register_storage(struct backup_storage *);

int backup_save_session(struct ap_session *ses);
void backup_restore_session(struct backup_data *d);

struct backup_mod *backup_find_mod(struct backup_data *d, uint8_t mod_id);
struct backup_tag *backup_find_tag(struct backup_data *d, uint8_t mod_id, uint8_t tag_id, int internal);
struct backup_tag *backup_add_tag(struct backup_mod *m, uint8_t id, int internal, const void *data, size_t size);
void backup_add_fd(struct backup_mod *m, int fd);

void backup_restore(int internal);
void backup_restore_fd();

#endif

