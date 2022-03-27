#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <pthread.h>
#include <limits.h>

#include "utils.h"
#include "triton.h"
#include "events.h"
#include "log.h"
#include "ppp.h"
#include "cli.h"

#include "memdebug.h"

#include "shaper.h"
#include "tc_core.h"

#define MAX_PARAM_COUNT 127

pthread_rwlock_t adv_shaper_lock = PTHREAD_RWLOCK_INITIALIZER;
LIST_HEAD(conf_adv_shaper_qdisc_list);
LIST_HEAD(conf_adv_shaper_class_list);
LIST_HEAD(conf_adv_shaper_filter_list);


static int parse_classid(__u32 *classid, char* str) {
	//CLASSID is 32-bit unsigned int
	//Format - XXXX:XXXX
	//         maj :min
	//CLASSID = (maj << 16) + min
	char* colon;
	__u32  maj, min;

	//colon = strchr(str, ':');
	//*colon = 0;
	maj = strtoul(str, &colon, 16);
	str = colon+1;

	min = strtoul(str, &colon, 16);
	//*colon = ':';
	//min = atoi(colon+1);

	if (maj > 0xffff)
		return -1;
	if (min > 0xffff)
		return -1;

	*classid = (maj << 16) + min;

	return 0;
}

static size_t __split_string(char ***res, const char *str, const char splitter, const size_t max_param) {
	char *begin = (char*)str;

	for (__u8 i = 0; i < max_param; ++i) {
		char *ptr = strchr(begin, splitter);
		if (ptr) {
			*res = _realloc(*res, (i+1)*sizeof(char*));
			(*res)[i] = _malloc((ptr-begin+1)*sizeof(char));

			*ptr = 0;
			strcpy((*res)[i], begin);
			*ptr = splitter;

			begin = ptr+1;
		} else {
			__u8 len = strlen(begin);
			*res = _realloc(*res, (i+1)*sizeof(char*));
			(*res)[i] = _malloc((len+1)*sizeof(char));

			strcpy((*res)[i], begin);

			return i + 1;
		}
	}

	return max_param;
}

//dest   - pointer for resulting array
//source - pointer for source array
//param_count - parameters count in source array
static size_t remove_empty_strings(char ***dest, char ***source, const size_t param_count)
{
	size_t filled_strings = 0;
	for (size_t i = 0; i < param_count; ++i) {
		if ( *((*source)[i]) ) {
			++filled_strings;
		}
	}

	if ( filled_strings ) {
		*dest = _malloc(filled_strings * sizeof(char*));

		size_t j = 0;
		for (size_t i = 0; i < param_count; ++i) {
			if ( *((*source)[i]) ) {
				(*dest)[j] = _malloc( (strlen( (*source)[i])+1 ) * sizeof(char) );
				strcpy( (*dest)[j], (*source)[i] );
				++j;
			}
		}
	}

	return filled_strings;
}

static size_t split_string(char ***res, const char *str, const char splitter, const size_t max_param)
{
	char **params = NULL;
	size_t parsed_params = __split_string(&params, str, splitter, max_param);

	char **cleared_params = NULL;
	size_t cleared_params_count = remove_empty_strings(&cleared_params, &params, parsed_params);

	if (params) {
		for (size_t i = 0; i < parsed_params; ++i) {
			_free(params[i]);
		}
		_free(params);
	}

	*res = cleared_params;
	return cleared_params_count;
}



static int load_qdisc_htb(struct adv_shaper_qdisc *qopt, char **params, size_t param_count) 
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: qdisc: htb: Cannot parse %s! (%s)\n", key, value)

	__u32 handle = 0;
	__u32 parentid = 0;
	__u32 r2q = 0;
	__u32 def_class = 0;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: qdisc: htb: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "handle")) {
			if (parse_classid(&handle, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "r2q")) {
			if (!u_parse_u32(value, &r2q)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "default")) {
			if (parse_classid(&def_class, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: qdisc: htb: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if (!handle || !parentid || !r2q || !def_class) {
		log_error("adv_shaper: qdisc: htb: Not enough items! Format - qdisc = htb handle HANDLE parent PARENTID r2q R2Q default DEF_CLASS\n");
		return -1;
	}

	qopt->handle = handle;
	qopt->parent = parentid;
	qopt->quantum = r2q;
	qopt->defcls = def_class;

	return 0;
#undef cannot_parse_log
}

static int load_qdisc_tbf(struct adv_shaper_qdisc *qopt, char **params, size_t param_count) 
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: qdisc: tbf: Cannot parse %s! (%s)\n", key, value)

	__u32 handle   = 0;
	__u32 parentid = 0;
	__u32 rate     = 0;
	__u32 burst    = 0;
	double latency = 0;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: qdisc: tbf: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "handle")) {
			if (parse_classid(&handle, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "rate")) {
			if (!u_parse_u32(value, &rate)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "burst")) {
			if (!u_parse_u32(value, &burst)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "latency")) {
			latency = (double)atoi(value) / 1000;
			if (!latency) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: qdisc: tbf: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if (!handle || !parentid || !rate || !burst || !latency) {
		log_error("adv_shaper: qdisc: tbf: Not enough columns! Format - qdisc = tbf handle HANDLE parent PARENTID rate RATE burst BURST latency LATENCY\n");
		return -1;
	}

	qopt->handle  = handle;
	qopt->parent  = parentid;
	qopt->rate    = rate;
	qopt->buffer  = burst;
	qopt->latency = latency;

	return 0;
#undef cannot_parse_log
}

static int load_qdisc_fq_codel(struct adv_shaper_qdisc *qopt, char **params, size_t param_count) 
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: qdisc: fq_codel: Cannot parse %s! (%s)\n", key, value)

	__u32 handle   = 0;
	__u32 parentid = 0;
	__u32 limit    = 0;
	__u32 flows    = 0;
	__u32 quantum  = 0;
	__u32 target   = 0;
	__u32 interval = 0;
	int ecn = -1;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];

		if (!strcmp(key, "ecn")) {
			ecn = 1;
			continue;
		} else if (!strcmp(key, "noecn")) {
			ecn = -1;
			continue;
		}

		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: qdisc: fq_codel: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "handle")) {
			if (parse_classid(&handle, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "limit")) {
			if (!u_parse_u32(value, &limit)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "flows")) {
			if (!u_parse_u32(value, &flows)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "quantum")) {
			if (!u_parse_u32(value, &quantum)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "target")) {
			target = atoi(value) * 1000;
			if (!target) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "interval")) {
			interval = atoi(value) * 1000;
			if (!interval) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: qdisc: fq_codel: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if (!handle || !parentid) {
		log_error("adv_shaper: qdisc: fq_codel: Not enough columns! Format - qdisc = fq_codel handle HANDLE parent PARENTID[limit LIMIT flows FLOWS quantum QUANTUM target TARGET interval INTERVAL ecn|noecn]\n");
		return -1;
	}

	qopt->handle   = handle;
	qopt->parent   = parentid;
	qopt->limit    = limit;
	qopt->flows    = flows;
	qopt->quantum  = quantum;
	qopt->target   = target;
	qopt->interval = interval;
	qopt->ecn      = ecn;

	return 0;
#undef cannot_parse_log
}

static int load_qdisc_sfq(struct adv_shaper_qdisc *qopt, char **params, size_t param_count) 
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: qdisc: sfq: Cannot parse %s! (%s)\n", key, value)

	__u32 handle   = 0;
	__u32 parentid = 0;
	__u32 perturb  = 0;
	__u32 limit    = 0;
	__u32 quantum  = 0;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: qdisc: sfq: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "handle")) {
			if (parse_classid(&handle, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "perturb")) {
			if (!u_parse_u32(value, &perturb)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "limit")) {
			if (!u_parse_u32(value, &limit)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "quantum")) {
			if (!u_parse_u32(value, &quantum)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: qdisc: sfq: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if (!handle || !parentid || !perturb) {
		log_error("adv_shaper: qdisc: sfq: Not enough columns! Format - qdisc = sfq handle HANDLE parent PARENTID perturb PERTURB[limit LIMIT quantum QUANTUM]\n");
		return -1;
	}

	qopt->handle  = handle;
	qopt->parent  = parentid;
	qopt->perturb = perturb;
	qopt->limit   = limit;
	qopt->quantum = quantum;

	return 0;
#undef cannot_parse_log
}

static void free_advanced_shaper_qdisc() {
	struct adv_shaper_qdisc* qdisc;
	while (!list_empty(&conf_adv_shaper_qdisc_list)) {
		qdisc = list_entry(conf_adv_shaper_qdisc_list.next, typeof(*qdisc), entry);
		list_del(&qdisc->entry);
		_free(qdisc);
	}
}

static struct adv_shaper_qdisc* preload_advanced_shaper_qdisc(char* opt_str)
{
	struct adv_shaper_qdisc *qdisc = NULL;

	char **params = NULL;
	size_t parsed_params = split_string(&params, opt_str, ' ', MAX_PARAM_COUNT);

	__u8 kind = 0;

	if (parsed_params >= 1) {
		if (!strcmp(params[0], "htb")) {
			kind = ADV_SHAPER_QDISC_HTB;
		} else if (!strcmp(params[0], "tbf")) {
			kind = ADV_SHAPER_QDISC_TBF;
		} else if (!strcmp(params[0], "sfq")) {
			kind = ADV_SHAPER_QDISC_SFQ;
		} else if (!strcmp(params[0], "fq_codel")) {
			kind = ADV_SHAPER_QDISC_FQ_CODEL;
		} else {
			log_error("adv_shaper: qdisc: Unknown qdisc (%s). Supported : htb,tbf,sfq,fq_codel  (%s)\n", params[0], opt_str);
			goto parse_end;
		}
	} else {
		log_error("adv_shaper: qdisc: Not enough columns! Format - qdisc = KIND,(KIND_PARAMS)  (%s)\n", opt_str);
		goto parse_end;
	}

	qdisc = _malloc(sizeof(struct adv_shaper_qdisc));

	__u8 sended_params = parsed_params - 1;

	if (kind == ADV_SHAPER_QDISC_HTB) {

		qdisc->kind = "htb";
		if (!load_qdisc_htb(qdisc, params+1, sended_params)) {
			log_info2("adv_shaper: qdisc: Loaded qdisc (%s) as (handle: 0x%x, parent: 0x%x, r2q: %u, defaut class: 0x%x)\n",
					opt_str, qdisc->handle, qdisc->parent, qdisc->quantum, qdisc->defcls);
		} else {
			log_error("adv_shaper: qdisc: Error while reading htb params (%s)\n", opt_str);
			_free(qdisc);
			qdisc = NULL;
			goto parse_end;
		}

	} else if (kind == ADV_SHAPER_QDISC_TBF) {

		qdisc->kind = "tbf";
		if (!load_qdisc_tbf(qdisc, params+1, sended_params)) {
			log_info2("adv_shaper: qdisc: Loaded qdisc (%s) as (handle: 0x%x, parent: 0x%x, rate: %u, burst: %u, latency: %f)\n",
					opt_str, qdisc->handle, qdisc->parent, qdisc->rate, qdisc->buffer, qdisc->latency);
		} else {
			log_error("adv_shaper: qdisc: Error while reading tbf params (%s)\n", opt_str);
			_free(qdisc);
			qdisc = NULL;
			goto parse_end;
		}

	} else if (kind == ADV_SHAPER_QDISC_SFQ) {

		qdisc->kind = "sfq";
		if (!load_qdisc_sfq(qdisc, params+1, sended_params)) {
			log_info2("adv_shaper: qdisc: Loaded qdisc (%s) as (handle: 0x%x, parent: 0x%x, perturb: %u, limit: %u, quantum: %u)\n",
					opt_str, qdisc->handle, qdisc->parent, qdisc->perturb, qdisc->limit, qdisc->quantum);
		} else {
			log_error("adv_shaper: qdisc: Error while reading sfq params (%s)\n", opt_str);
			_free(qdisc);
			qdisc = NULL;
			goto parse_end;
		}

	} else if (kind == ADV_SHAPER_QDISC_FQ_CODEL) {

		qdisc->kind = "fq_codel";
		if (!load_qdisc_fq_codel(qdisc, params+1, sended_params)) {
			log_info2("adv_shaper: qdisc: Loaded qdisc (%s) as (handle: 0x%x, parent: 0x%x, limit: %u, flows: %u, quantum: %u, target: %u, interval: %u, ecn %d)\n",
					opt_str, qdisc->handle, qdisc->parent, qdisc->limit, qdisc->flows, qdisc->quantum, qdisc->target, qdisc->interval, qdisc->ecn);
		} else {
			log_error("adv_shaper: qdisc: Error while reading fq_codel params (%s)\n", opt_str);
			_free(qdisc);
			qdisc = NULL;
			goto parse_end;
		}

	} else {

	}

parse_end:
	if (params) {
		for (size_t i = 0; i < parsed_params; ++i) {
			_free(params[i]);
		}
		_free(params);
	}


	return qdisc;
}

//!!!IMPORTANT!!!
//FIRST qdisc == root qdisc
//Config pattern:
//HTB:
//qdisc = KIND,HANDLE,PARENT,r2q,DEF_CLASS
static int load_advanced_shaper_qdisc(struct conf_sect_t *s) {
	free_advanced_shaper_qdisc();

	struct conf_option_t *opt = NULL;

	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "qdisc"))
			continue;
		if (!opt->val)
			continue;

		struct adv_shaper_qdisc *qdisc = preload_advanced_shaper_qdisc(opt->val);

		if (qdisc) {
			list_add_tail(&qdisc->entry, &conf_adv_shaper_qdisc_list);
		} else {
			return -1;
		}
	}
	return 0;
}

static void free_advanced_shaper_class() {
	struct adv_shaper_class* class;
	while (!list_empty(&conf_adv_shaper_class_list)) {
		class = list_entry(conf_adv_shaper_class_list.next, typeof(*class), entry);
		list_del(&class->entry);
		_free(class);
	}
}

static struct adv_shaper_class* preload_advanced_shaper_class(char* opt_str) 
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: class: Cannot parse %s! (%s)\n", key, value)

	struct adv_shaper_class *adv_shaper_class_item = NULL;

	//CLASSID is 32-bit unsigned int
	//Format - XXXX:XXXX
	//         maj :min
	//CLASSID = (maj << 16) + min
	__u32 classid  = 0;

	//Root classid
	__u32 parentid = 0;

	//Predefined speed for class
	__u32 rate = 0;
	__u32 ceil = 0;
	__u32 burst = 0;
	__u32 cburst = 0;

	char **params = NULL;
	size_t param_count = split_string(&params, opt_str, ' ', MAX_PARAM_COUNT);

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: class: Not enough parameters for building key-value pair! key == (%s)\n", key);
			goto parse_end;
		}
		if (!strcmp(key, "classid")) {
			if (parse_classid(&classid, value)) {
				cannot_parse_log(key, value);
				goto parse_end;
			}
		} else if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				goto parse_end;
			}
		} else if (!strcmp(key, "rate")) {
			if (!u_parse_u32(value, &rate)) {
				cannot_parse_log(key, value);
				goto parse_end;
			}
		} else if (!strcmp(key, "burst")) {
			if (!u_parse_u32(value, &burst)) {
				cannot_parse_log(key, value);
				goto parse_end;
			}
		} else if (!strcmp(key, "cburst")) {
			if (!u_parse_u32(value, &cburst)) {
				cannot_parse_log(key, value);
				goto parse_end;
			}
		} else if (!strcmp(key, "ceil")) {
			if (!u_parse_u32(value, &ceil)) {
				cannot_parse_log(key, value);
				goto parse_end;
			}
		} else {
			log_error("adv_shaper: class: Unknown key! key == (%s)\n", key);
			goto parse_end;
		}
	}

	if (!classid || !parentid) {
		log_error("adv_shaper: class: Not enough columns! Format - class = classid CLASSID parent PARENTID [rate RATE burst BURST cburst CBURST ceil CEIL]  (%s)\n", opt_str);
		goto parse_end;
	}

	log_info2("adv_shaper: class: Loaded class (%s) as (0x%x, 0x%x, %u, %u %u)\n", opt_str, classid, parentid, rate, burst, cburst);

	adv_shaper_class_item = _malloc(sizeof(struct adv_shaper_class));

	adv_shaper_class_item->classid  = classid;
	adv_shaper_class_item->parentid = parentid;
	adv_shaper_class_item->ceil     = ceil    * 1000 / 8;
	adv_shaper_class_item->rate     = rate    * 1000 / 8;
	adv_shaper_class_item->burst    = burst   * 1000 / 8;
	adv_shaper_class_item->cburst   = cburst  * 1000 / 8;

parse_end:
	for (size_t i = 0; i < param_count; ++i) {
		_free(params[i]);
	}
	_free(params);

	return adv_shaper_class_item;
#undef cannot_parse_log
}

//Config pattern:
//class = CLASSID,PARENTID,RATE,BURST,CBURST
static int load_advanced_shaper_class(struct conf_sect_t *s) {
	free_advanced_shaper_class();

	struct conf_option_t *opt = NULL;

	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "class"))
			continue;
		if (!opt->val)
			continue;

		struct adv_shaper_class* adv_shaper_class_item = preload_advanced_shaper_class(opt->val);

		if (adv_shaper_class_item) {
			list_add_tail(&adv_shaper_class_item->entry, &conf_adv_shaper_class_list);
		} else {
			return -1;
		}
	}
	return 0;
}

static void free_advanced_shaper_filter() {
	struct adv_shaper_filter* filter;
	while (!list_empty(&conf_adv_shaper_filter_list)) {
		filter = list_entry(conf_adv_shaper_filter_list.next, typeof(*filter), entry);

		//Check if filter can using keys
		//BUT PREFERRED TO INITIALIZE ALL VALUES
		if (filter->kind == ADV_SHAPER_FILTER_NET || filter->kind == ADV_SHAPER_FILTER_NET6 || filter->kind == ADV_SHAPER_FILTER_U32_RAW) {
			if (filter->keys) {
				_free(filter->keys);
			}
		}

		list_del(&filter->entry);
		_free(filter);
	}
}

static int load_filter_net(struct adv_shaper_filter *fopt, char **params, size_t param_count)
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: filter: net: Cannot parse %s! (%s)\n", key, value)

	__u32 parentid = 0;
	__u32 priority = 0;
	struct in_addr prefix;
	__u8 prefix_len = 0;
	int off = 0;
	int offmask = 0;
	__u32 classid = 0;

	__u32 ip_mask = 0;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (!strcmp(key, "src")) {
			off = 12;
			offmask = 0;
			continue;
		} else if (!strcmp(key, "dst")) {
			off = 16;
			offmask = 0;
			continue;
		}
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: filter: net: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "priority")) {

			priority = strtol(value, NULL, 10);

		} else if (!strcmp(key, "ip")) {
			if (u_parse_ip4cidr(value, &prefix, &prefix_len)) {
				ip_mask = htonl(0xffffffff << (32 - prefix_len));
			} else {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "classid")) {
			if (parse_classid(&classid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: filter: net: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if ( !parentid || !priority || !classid ) {
		log_error("adv_shaper: filter: net: Not enough items! Format - filter = net parent PARENTID priority PRIO ip NET src|dst classid CLASSID\n");
		return -1;
	}

	fopt->parentid  = parentid;
	fopt->classid   = classid;
	fopt->priority  = priority;

	fopt->key_count = 1;
	fopt->keys      = _malloc( sizeof(struct adv_shaper_u32_key) );

	fopt->keys[0].val       = prefix.s_addr;
	fopt->keys[0].mask      = ip_mask;
	fopt->keys[0].off       = off;
	fopt->keys[0].offmask   = offmask;

	return 0;
#undef cannot_parse_log
}

static int load_filter_net6(struct adv_shaper_filter *fopt, char **params, size_t param_count)
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: filter: net6: Cannot parse %s! (%s)\n", key, value)

	__u32 parentid = 0;
	__u32 priority = 0;
	struct in6_addr prefix;
	__u8 prefix_len = 0;
	int off = 0;
	int offmask = 0;
	__u32 classid = 0;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (!strcmp(key, "src")) {
			off = 8;
			offmask = 0;
			continue;
		} else if (!strcmp(key, "dst")) {
			off = 24;
			offmask = 0;
			continue;
		}
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: filter: net6: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "priority")) {

			priority = strtol(value, NULL, 10);

		} else if (!strcmp(key, "ip6")) {
			if (u_parse_ip6cidr(value, &prefix, &prefix_len)) {

			} else {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "classid")) {
			if (parse_classid(&classid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: filter: net: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if ( !parentid || !priority || !classid ) {
		log_error("adv_shaper: filter: net6: Not enough items! Format - filter = net6 parent PARENTID priority PRIO ip6 NET src|dst classid CLASSID\n");
		return -1;
	}

	fopt->parentid  = parentid;
	fopt->classid   = classid;
	fopt->priority  = priority;

	__u8 key_count = prefix_len / 32;
	if (prefix_len % 32) {
		++key_count;
	}

	fopt->key_count = key_count;
	fopt->keys = NULL;

	if (key_count) {
		fopt->keys = _malloc(key_count * sizeof(struct adv_shaper_u32_key));

		for (__u8 i = 0; i < prefix_len; i += 32) {
			size_t key_num = i/32;

			fopt->keys[key_num].val = prefix.s6_addr32[key_num];

			if (i+31 < prefix_len) {
				fopt->keys[key_num].mask = 0xffffffff;
			} else {
				fopt->keys[key_num].mask = htonl(0xffffffff << (32 - (prefix_len - i)));
			}

			fopt->keys[key_num].off = off + 4*(i/32);
			fopt->keys[key_num].offmask = offmask;
		}
	}

	return 0;
#undef cannot_parse_log

}

static int load_filter_fw(struct adv_shaper_filter *fopt, char **params, size_t param_count)
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: filter: fw: Cannot parse %s! (%s)\n", key, value)

	__u32 parentid = 0;
	__u32 priority = 0;
	__u32 classid = 0;
	__u32 fwmark = 0;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: filter: fw: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "priority")) {

			priority = strtol(value, NULL, 10);

		} else if (!strcmp(key, "handle")) {

			fwmark = strtol(value, NULL, 10);

		} else if (!strcmp(key, "classid")) {
			if (parse_classid(&classid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: filter: fw: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if ( !parentid || !priority || !fwmark || !classid ) {
		log_error("adv_shaper: filter: fw: Not enough items! Format - filter = fw parent PARENTID priority PRIO handle HANDLE classid CLASSID\n");
		return -1;
	}

	fopt->parentid  = parentid;
	fopt->classid   = classid;
	fopt->priority  = priority;
	fopt->fwmark    = fwmark;

	fopt->key_count = 0;
	fopt->keys = NULL;

	return 0;
#undef cannot_parse_log
}

static int load_filter_u32(struct adv_shaper_filter *fopt, char **params, size_t param_count)
{
#define cannot_parse_log(key, value)  \
	log_error("adv_shaper: filter: u32: Cannot parse %s! (%s)\n", key, value)

	__u32 parentid = 0;
	__u32 priority = 0;
	__u32 val      = 0;
	__u32 val_mask = 0;
	int off = 0;
	int offmask = 0;
	__u32 classid = 0;

	char *key = NULL;
	char *value = NULL;

	for (size_t i = 0; i < param_count; ++i) {
		key = params[i];
		if (i+1 < param_count) {
			value = params[i+1];
			++i;
		} else {
			log_error("adv_shaper: filter: u32: Not enough parameters for building key-value pair! key == (%s)\n", key);
			return -1;
		}
		if (!strcmp(key, "parent")) {
			if (parse_classid(&parentid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else if (!strcmp(key, "priority")) {

			priority = strtol(value, NULL, 10);

		} else if (!strcmp(key, "value")) {

			val = ntohl(strtol(value, NULL, 16));

		} else if (!strcmp(key, "mask")) {

			val_mask = ntohl(strtol(value, NULL, 16));

		} else if (!strcmp(key, "offset")) {

			off = strtol(value, NULL, 10);

		} else if (!strcmp(key, "offmask")) {

			offmask = strtol(value, NULL, 10);

		} else if (!strcmp(key, "classid")) {
			if (parse_classid(&classid, value)) {
				cannot_parse_log(key, value);
				return -1;
			}
		} else {
			log_error("adv_shaper: filter: u32: Unknown key! key == (%s)\n", key);
			return -1;
		}
	}

	if ( !parentid || !priority || !classid ) {
		log_error("adv_shaper: filter: u32: Not enough items! Format - filter = u32 parent PARENTID priority PRIO value VAL mask VAL_MASK offset OFFSET offmask OFFMASK classid CLASSID\n");
		return -1;
	}

	fopt->parentid  = parentid;
	fopt->classid   = classid;
	fopt->priority  = priority;

	fopt->key_count = 1;
	fopt->keys      = _malloc( sizeof(struct adv_shaper_u32_key) );

	fopt->keys[0].val       = val;
	fopt->keys[0].mask      = val_mask;
	fopt->keys[0].off       = off;
	fopt->keys[0].offmask   = offmask;

	return 0;
#undef cannot_parse_log
}

static struct adv_shaper_filter* preload_advanced_shaper_filter(char *opt_str)
{
	struct adv_shaper_filter *filter = NULL;

	char **params = NULL;
	size_t parsed_params = split_string(&params, opt_str, ' ', MAX_PARAM_COUNT);

	__u8 kind = 0;

	if (parsed_params >= 1) {
		if (!strcmp(params[0], "net")) {
			kind = ADV_SHAPER_FILTER_NET;
		} else if (!strcmp(params[0], "net6")) {
			kind = ADV_SHAPER_FILTER_NET6;
		} else if (!strcmp(params[0], "fw")) {
			kind = ADV_SHAPER_FILTER_FW;
		} else if (!strcmp(params[0], "u32")) {
			kind = ADV_SHAPER_FILTER_U32_RAW;
		} else {
			log_error("adv_shaper: filter: Unknown filter (%s). Supported : net,net6,fw,u32  (%s)\n", params[0], opt_str);
			goto parse_end;
		}
	} else {
		log_error("adv_shaper: filter: Not enough items! Format - filter = KIND (KIND_PARAMS)  (%s)\n", opt_str);
		goto parse_end;
	}

	filter = _malloc(sizeof(struct adv_shaper_filter));

	size_t sended_params = parsed_params - 1;

	filter->kind = kind;
	if (kind == ADV_SHAPER_FILTER_NET) {
		if (!load_filter_net(filter, params+1, sended_params)) {
			char net_buff[17];
			if (filter->key_count) {
				u_inet_ntoa(filter->keys[0].val, net_buff);
				log_info2("adv_shaper: filter: Loaded filter (%s) as (parent 0x%x, classid 0x%x, priority %u, ip %s/0x%x, offset %u) \n",
						opt_str, filter->parentid, filter->classid, filter->priority, net_buff, filter->keys[0].mask, filter->keys[0].off);
			} else {
				log_info2("adv_shaper: filter: While loading filter (%s) no keys created!\n", opt_str);
				_free(filter);
				filter = NULL;
				goto parse_end;
			}
		} else {
			log_error("adv_shaper: filter: Error while reading net filter params (%s)\n", opt_str);
			_free(filter);
			filter = NULL;
			goto parse_end;
		}
	} else if (kind == ADV_SHAPER_FILTER_NET6) {
		if (!load_filter_net6(filter, params+1, sended_params)) {
			log_info2("adv_shaper: filter: net6: Loaded filter (%s) as (parent 0x%x, classid 0x%x, priority %u) \n",
					opt_str, filter->parentid, filter->classid, filter->priority);

			if (!filter->key_count) {
				log_info2("adv_shaper: filter: net6: No keys created! You specified ip6 as (::/0)?\n");
			}

			for (size_t i = 0; i < filter->key_count; ++i) {
				log_error("adv_shaper: filter: net6: Loaded filter (key %lu: value 0x%x, mask 0x%x, offset %u, offmask 0x%x)!\n",
					i, ntohl(filter->keys[i].val), ntohl(filter->keys[i].mask), filter->keys[i].off, filter->keys[i].offmask);
			}
		} else {
			log_error("adv_shaper: filter: Error while reading net6 filter params (%s)\n", opt_str);
			_free(filter);
			filter = NULL;
			goto parse_end;
		}

	} else if (kind == ADV_SHAPER_FILTER_FW) {
		if (!load_filter_fw(filter, params+1, sended_params)) {
			log_info2("adv_shaper: filter: fw: Loaded filter (%s) as (parent 0x%x, classid 0x%x, priority %u, handle %u) \n",
					opt_str, filter->parentid, filter->classid, filter->priority, filter->fwmark);
		} else {
			log_error("adv_shaper: filter: Error while reading fw filter params (%s)\n", opt_str);
			_free(filter);
			filter = NULL;
			goto parse_end;
		}
	} else if (kind == ADV_SHAPER_FILTER_U32_RAW) {
		if (!load_filter_u32(filter, params+1, sended_params)) {
			if (filter->key_count) {
				log_info2("adv_shaper: filter: u32: Loaded filter (%s) as (parent 0x%x, priority %u, value 0x%x, mask 0x%x, offset %u, classid 0x%x)\n",
						opt_str, filter->parentid, filter->priority, filter->keys[0].val, filter->keys[0].mask, filter->keys[0].off, filter->classid);
			} else {
				log_info2("adv_shaper: filter: While loading filter (%s) no keys created!\n", opt_str);
				_free(filter);
				filter = NULL;
				goto parse_end;
			}
		} else {
			log_error("adv_shaper: filter: Error while reading u32 filter params (%s)\n", opt_str);
			_free(filter);
			filter = NULL;
			goto parse_end;
		}
	} else {

	}

parse_end:
	if (params) {
		for (size_t i = 0; i < parsed_params; ++i) {
			_free(params[i]);
		}
		_free(params);
	}

	return filter;
}


//Config pattern:
//filter_net = PARENT,PRIO,IP4CIDR,(SRC/DST),FLOWID(aka CLASSID)
static int load_advanced_shaper_filter(struct conf_sect_t *s) 
{
	free_advanced_shaper_filter();

	struct conf_option_t *opt;

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "filter")) {
			if (!opt->val)
				continue;

			struct adv_shaper_filter *adv_shaper_filter_item = preload_advanced_shaper_filter(opt->val);

			if (adv_shaper_filter_item) {
				list_add_tail(&adv_shaper_filter_item->entry, &conf_adv_shaper_filter_list);
			} else {
				return -1;
			}
		}
	}
	return 0;
}

//!!!IMPORTANT!!!
//FIRST qdisc == root qdisc
//Config pattern:
//HTB:
//qdisc = KIND,HANDLE,PARENT,r2q,DEF_CLASS
static int check_advanced_shaper_qdisc(struct conf_sect_t *s) {
	struct conf_option_t *opt = NULL;

	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "qdisc"))
			continue;
		if (!opt->val)
			continue;

		struct adv_shaper_qdisc *qdisc = preload_advanced_shaper_qdisc(opt->val);

		if (qdisc) {
			_free(qdisc);
		} else {
			return -1;
		}
	}
	return 0;
}


//Config pattern:
//class = CLASSID,PARENTID,RATE,BURST,CBURST
static int check_advanced_shaper_class(struct conf_sect_t *s) {
	struct conf_option_t *opt = NULL;

	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "class"))
			continue;
		if (!opt->val)
			continue;

		struct adv_shaper_class* adv_shaper_class_item = preload_advanced_shaper_class(opt->val);

		if (adv_shaper_class_item) {
			_free(adv_shaper_class_item);
		} else {
			return -1;
		}
	}

	return 0;
}

static int check_advanced_shaper_filter(struct conf_sect_t *s) 
{
	struct conf_option_t *opt;

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "filter")) {
			if (!opt->val)
				continue;

			struct adv_shaper_filter *adv_shaper_filter_item = preload_advanced_shaper_filter(opt->val);

			if (adv_shaper_filter_item) {
				_free(adv_shaper_filter_item);
			} else {
				return -1;
			}
		}
	}

	return 0;
}


static int check_advanced_shaper(struct conf_sect_t *s) 
{
	log_info2("adv_shaper: Configuration checkout...\n");
	int res = 0;
	res |= check_advanced_shaper_qdisc(s);
	res |= check_advanced_shaper_class(s);
	res |= check_advanced_shaper_filter(s);

	if (res) {
		log_info2("adv_shaper: Configuration checkout FAILED!\n");
	} else {
		log_info2("adv_shaper: Configuration checkout SUCCESS!\n");
	}

	return res;
}

void load_advanced_shaper()
{
	struct conf_sect_t *s = conf_get_section("advanced_shaper");

	log_debug("adv_shaper: load adv_shaper section BEGIN\n");
	if (s) {
		pthread_rwlock_wrlock(&adv_shaper_lock);

		if (!check_advanced_shaper(s)) {
			load_advanced_shaper_qdisc(s);
			load_advanced_shaper_class(s);
			load_advanced_shaper_filter(s);
		}

		pthread_rwlock_unlock(&adv_shaper_lock);
	}
	log_debug("adv_shaper: load adv_shaper section END\n");
}
