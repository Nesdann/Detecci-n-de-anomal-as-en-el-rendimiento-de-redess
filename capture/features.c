#include <stdio.h>
#include "features.h"
#include "time_utils.h"
#include "flow.h"
#include "flow_table.h"

void extract_features(const flow_t *f)
{
    double dur = timeval_diff(f->last_seen, f->first_seen);
    double pps = f->packets / dur;
    double bps = f->bytes / dur;
    double avg_pkt = (double)f->bytes / f->packets;

    FILE *fp = fopen("test_ata.csv", "a");
    if (!fp) return;

    fprintf(fp,
        "%u,%u,%u,%.3f,%u,%u,%.3f,%.3f,%.3f\n",
        f->key.src_ip,
        f->key.dst_ip,
        f->key.proto,
        dur,
        f->packets,
        f->bytes,
        pps,
        bps,
        avg_pkt
    );

    fclose(fp);
}

