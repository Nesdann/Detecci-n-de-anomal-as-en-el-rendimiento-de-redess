#ifndef TIME_UTILS_H
#define TIME_UTILS_H

#include <sys/time.h>
#include <stdint.h>
#include "flow.h"
#include "flow_table.h"

double timeval_diff(struct timeval a, struct timeval b);

void flow_update(flow_t *f, struct timeval ts, uint32_t pkt_len);

#endif
