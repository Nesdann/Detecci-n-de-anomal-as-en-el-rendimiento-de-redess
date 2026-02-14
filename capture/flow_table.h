#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "flow.h"

#define FLOW_TABLE_SIZE 65536
#define EXPIRE_INTERVAL 1   // segundo
#define ACTIVE_TIMEOUT 0.5   // segundos


typedef struct flow_node {
    flow_t flow;
    struct flow_node *next;
} flow_node_t;


typedef struct {
    flow_node_t *buckets[FLOW_TABLE_SIZE];
} flow_table_t;


void flow_table_init(flow_table_t *t);


flow_t *flow_table_get_or_create(flow_table_t *t,
                                 const flow_key_t *key,
                                 const struct timeval *ts,
                                 uint32_t pkt_len);

void flow_table_dump(flow_table_t *t);

void flow_table_expire(flow_table_t *t,
                       const struct timeval *now);

#endif
