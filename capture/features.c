#include <stdio.h>
#include <arpa/inet.h>
#include "features.h"
#include "time_utils.h"
#include "flow.h"
#include "flow_table.h"
#include <math.h>


void flow_compute_time_features(flow_t *f,
                                double *duration,
                                double *mean_iat,
                                double *std_iat,
                                double *idle_mean,
                                double *idle_ratio)
{
    *duration = timeval_diff(f->last_seen, f->first_seen);

    if (f->iat_count > 0) {
        *mean_iat = f->iat_sum / f->iat_count;

        double variance =
            (f->iat_sq_sum / f->iat_count) -
            ((*mean_iat) * (*mean_iat));

        if (variance < 0)
            variance = 0;

        *std_iat = sqrt(variance);
    } else {
        *mean_iat = 0;
        *std_iat  = 0;
    }

    if (f->idle_count > 0)
        *idle_mean = f->idle_time_total / f->idle_count;
    else
        *idle_mean = 0;

    if (*duration > 0)
        *idle_ratio = f->idle_time_total / (*duration);
    else
        *idle_ratio = 0;
}


void extract_features(const flow_t *f)
{
    double duration, mean_iat, std_iat, idle_mean, idle_ratio;
    if (f->packets == 0)
    return;

    double dur = timeval_diff(f->last_seen, f->first_seen);
    if (dur <= 0.0)
        dur = 1e-6;

    double pps = f->packets / dur;
    double bps = f->bytes / dur;

    double dir_ratio = 0.0;
    if (f->bwd_packets > 0)
        dir_ratio = (double)f->fwd_packets / f->bwd_packets;

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &f->key.src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &f->key.dst_ip, dst, sizeof(dst));


    flow_compute_time_features(f,
                              &duration,
                              &mean_iat,
                              &std_iat,
                              &idle_mean,
                              &idle_ratio);

        unsigned long total_packets = f->fwd_packets + f->bwd_packets;
    unsigned long total_bytes = f->fwd_bytes + f->bwd_bytes;

    double syn_ratio = (total_packets > 0) ? (double)f->syn_count / total_packets : 0.0;
    double rst_ratio = (total_packets > 0) ? (double)f->rst_count / total_packets : 0.0;
    double ack_ratio = (total_packets > 0) ? (double)f->ack_count / total_packets : 0.0;

    double avg_pkt = (total_packets > 0) ? (double)total_bytes / total_packets : 0.0;

    double byte_ratio = (f->bwd_bytes > 0) ? 
                        (double)f->fwd_bytes / f->bwd_bytes : 0.0;

    int is_short_flow = (dur < 1.0) ? 1 : 0;


    FILE *fp = fopen("test_ata.csv", "a");
    if (!fp) return;


    int label = 1; // 0 = normal, 1 = anomalous

        fprintf(fp,
    "%s,%u,%s,%u,%u,"
    "%lu,%lu,%lu,%lu,"
    "%lu,%lu,"
    "%u,%u,%u,%u,"
    "%.6f,%.6f,%.6f,"
    "%.6f,%.6f,%.6f,"
    "%.6f,%.6f,%.6f,"
    "%.6f,%.6f,%d,%.6f,%d\n",

        src,
        f->key.src_port,
        dst,
        f->key.dst_port,
        f->key.proto,

        f->fwd_packets,
        f->bwd_packets,
        f->fwd_bytes,
        f->bwd_bytes,

        total_packets,
        total_bytes,

        f->syn_count,
        f->ack_count,
        f->fin_count,
        f->rst_count,

        syn_ratio,
        rst_ratio,
        ack_ratio,

        dur,
        pps,
        bps,

        dir_ratio,
        byte_ratio,
        avg_pkt,

        std_iat,
        idle_ratio,
        is_short_flow,
        dur,
        label
);



fclose(fp);

}

