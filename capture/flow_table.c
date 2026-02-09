#include <stdlib.h>
#include <string.h>
#include "flow_table.h"
#include <stdio.h>
#include <arpa/inet.h>

uint32_t hash_flow_key(const flow_key_t *k) {
    uint32_t h = 2166136261u;
    h = (h ^ k->src_ip)   * 16777619;
    h = (h ^ k->dst_ip)   * 16777619;
    h = (h ^ k->src_port) * 16777619;
    h = (h ^ k->dst_port) * 16777619;
    h = (h ^ k->proto)    * 16777619;
    return h;
}

void flow_table_init(flow_table_t *t) {
    for (int i = 0; i < FLOW_TABLE_SIZE; i++)
        t->buckets[i] = NULL;
}

flow_t *flow_table_get_or_create(flow_table_t *t,
                                 const flow_key_t *key,
                                 const struct timeval *ts,
                                 uint32_t pkt_len)
{
    uint32_t h = hash_flow_key(key) % FLOW_TABLE_SIZE;
    flow_node_t *n = t->buckets[h];

    while (n) {
        if (memcmp(&n->flow.key, key, sizeof(flow_key_t)) == 0) {
            n->flow.packets++;
            n->flow.bytes += pkt_len;
            n->flow.last_seen = *ts;
            return &n->flow;
        }
        n = n->next;
    }

    flow_node_t *new = malloc(sizeof(flow_node_t));
    new->flow.key = *key;
    new->flow.packets = 1;
    new->flow.bytes = pkt_len;
    new->flow.first_seen = *ts;
    new->flow.last_seen  = *ts;

    new->next = t->buckets[h];//conectarlo al nodo viejo o null
    t->buckets[h] = new;

    return &new->flow;
}

void flow_table_dump(flow_table_t *t) {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        flow_node_t *n = t->buckets[i];
        while (n) {
            inet_ntop(AF_INET, &n->flow.key.src_ip, src, sizeof(src));
            inet_ntop(AF_INET, &n->flow.key.dst_ip, dst, sizeof(dst));

            printf("%s:%u -> %s:%u prototable=%u packetstable=%lu bytestable=%lu\n",
                   src, n->flow.key.src_port,
                   dst, n->flow.key.dst_port,
                   n->flow.key.proto,
                   n->flow.packets,
                   n->flow.bytes);

            n = n->next;
        }
    }
}
