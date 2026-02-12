#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <sys/time.h>

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} flow_key_t;


typedef struct {
    flow_key_t key;

    uint64_t packets;
    uint64_t bytes;

    uint64_t fwd_packets;
    uint64_t bwd_packets;

    uint64_t fwd_bytes;
    uint64_t bwd_bytes;

    uint32_t syn_count;
    uint32_t ack_count;
    uint32_t fin_count;
    uint32_t rst_count;

    uint32_t initiator_ip;
    uint16_t initiator_port;

    struct timeval first_seen;
    struct timeval last_seen;
} flow_t;




#endif