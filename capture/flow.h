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

    struct timeval first_seen;
    struct timeval last_seen;
} flow_t;



#endif