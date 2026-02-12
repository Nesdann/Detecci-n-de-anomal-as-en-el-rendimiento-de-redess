#include <stdlib.h>
#include <string.h>
#include "flow_table.h"
#include <stdio.h>
#include <arpa/inet.h>
#include "time_utils.h"
#include "features.h"

uint32_t hash_flow_key(const flow_key_t *k) {
    uint32_t h = 2166136261u;
    h = (h ^ k->src_ip)   * 16777619;
    h = (h ^ k->dst_ip)   * 16777619;
    h = (h ^ k->src_port) * 16777619;
    h = (h ^ k->dst_port) * 16777619;
    h = (h ^ k->proto)    * 16777619;
    return h;
}

flow_key_t normalize_key(flow_key_t k)
{
    flow_key_t res;
    res=k;//se puede? o hacer una fun cpy_key para mas abtraccion
    if (k.src_ip > k.dst_ip ||
       (k.src_ip == k.dst_ip && k.src_port > k.dst_port))
    {
        res.src_ip = k.dst_ip;
        res.dst_ip = k.src_ip;

        res.src_port = k.dst_port;
        res.dst_port = k.src_port;
    }
    return res;
}


void flow_table_init(flow_table_t *t) {
    for (int i = 0; i < FLOW_TABLE_SIZE; i++)
        t->buckets[i] = NULL;
}

flow_t *flow_table_get_or_create(flow_table_t *t,
                                 const flow_key_t *key_original,
                                 const struct timeval *ts,
                                 uint32_t pkt_len)
{
    flow_key_t keyN = normalize_key(*key_original);

    uint32_t h = hash_flow_key(&keyN) % FLOW_TABLE_SIZE;
    flow_node_t *n = t->buckets[h];

    while (n) {
        if (memcmp(&n->flow.key, &keyN, sizeof(flow_key_t)) == 0) {
            /*n->flow.packets++;
            n->flow.bytes += pkt_len;
            n->flow.last_seen = *ts;*/
            return &n->flow;
        }
        n = n->next;
    }

    // no existe => crear
    flow_node_t *new = malloc(sizeof(flow_node_t));

    new->flow.key = keyN;
    new->flow.packets = 1;
    new->flow.bytes = pkt_len;
    new->flow.first_seen = *ts;
    new->flow.last_seen = *ts;

    new->flow.initiator_ip = key_original->src_ip;
    new->flow.initiator_port = key_original->src_port;

    new->flow.fwd_packets = 0;
    new->flow.bwd_packets = 0;
    new->flow.fwd_bytes = 0;
    new->flow.bwd_bytes = 0;
    new->flow.syn_count=0;
    new->flow.rst_count=0;
    new->flow.fin_count=0;
    new->flow.ack_count=0;

    //
    new->flow.iat_count=0;
    new->flow.iat_max=0;
    new->flow.iat_min=0;
    new->flow.iat_sq_sum=0;
    new->flow.iat_sq_sum=0;
    new->flow.idle_time_total=0;
    new->flow.idle_count=0;

    new->next = t->buckets[h];
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



void flow_table_expire(flow_table_t *t,
                       const struct timeval *now)
{
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {

        flow_node_t **pp = &t->buckets[i];

        while (*pp) {
            flow_node_t *n = *pp;

            double active =
                timeval_diff(n->flow.last_seen,
                             n->flow.first_seen);

            if (active >= ACTIVE_TIMEOUT) {

                extract_features(&n->flow);
                printf("EXPIRA y extrae flow %u packets %lu bytes\n",
                n->flow.packets,
                n->flow.bytes);

                *pp = n->next;
                free(n);

            } else {
                pp = &n->next;
            }
        }
    }
}


