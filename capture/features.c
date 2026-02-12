#include <stdio.h>
#include <arpa/inet.h>
#include "features.h"
#include "time_utils.h"
#include "flow.h"
#include "flow_table.h"

void extract_features(const flow_t *f)
{
    if (f->packets == 0)
    return;

    double dur = timeval_diff(f->last_seen, f->first_seen);
    if (dur <= 0.0)
        dur = 1e-6;

    double pps = f->packets / dur;
    double bps = f->bytes / dur;
    double avg_pkt = (double)f->bwd_bytes / f->packets;

    double dir_ratio = 0.0;
if (f->bwd_packets > 0)
    dir_ratio = (double)f->fwd_packets / f->bwd_packets;

char src[INET_ADDRSTRLEN];
char dst[INET_ADDRSTRLEN];

inet_ntop(AF_INET, &f->key.src_ip, src, sizeof(src));
inet_ntop(AF_INET, &f->key.dst_ip, dst, sizeof(dst));

FILE *fp = fopen("test.csv", "a");
if (!fp) return;

fprintf(fp,
    "%s,%u,%s,%u,%u,"
    "%lu,%lu,%lu,%lu,"
    "%u,%u,%u,%u,"
    "%.6f,%lu,%lu,"
    "%.6f,%.6f,%.6f,%.6f\n",

    src,
    f->key.src_port,
    dst,
    f->key.dst_port,
    f->key.proto,

    f->fwd_packets,
    f->bwd_packets,
    f->fwd_bytes,
    f->bwd_bytes,

    f->syn_count,
    f->ack_count,
    f->fin_count,
    f->rst_count,

    dur,
    f->packets,
    f->bytes,

    pps,
    bps,
    avg_pkt,
    dir_ratio
);

fclose(fp);

}

