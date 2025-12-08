/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RT_NAMES_H_
#define RT_NAMES_H_ 1

#include <asm/types.h>

const char *rtnl_rttable_n2a(__u32 id, char *buf, int len);
const char *rtnl_dsfield_get_name(int id);

int rtnl_rttable_a2n(__u32 *id, const char *arg);

extern int numeric;

#endif
