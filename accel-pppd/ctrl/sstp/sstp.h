#ifndef __SSTP_H
#define __SSTP_H

struct sstp_stat_t
{
	unsigned int starting;
	unsigned int active;
};

void sstp_stat_get(struct sstp_stat_t *stat);
unsigned int sstp_stat_starting(void);
unsigned int sstp_stat_active(void);

#endif
