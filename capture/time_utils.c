#include "time_utils.h"
#include <stdio.h>
#include "flow.h"
#include "flow_table.h"
#include <stdint.h>

double timeval_diff(struct timeval a, struct timeval b)
{
    return (double)(a.tv_sec - b.tv_sec) +
           (double)(a.tv_usec - b.tv_usec) / 1000000.0;
}


void flow_update(flow_t *f, struct timeval ts, uint32_t pkt_len)
{
    /* primer paquete */
    if (f->packets == 0) {
        f->first_seen = ts;
        f->last_seen  = ts;
    } else {
        double iat = timeval_diff(ts,f->last_seen);
        //printf("IAT: %f\n", iat);


        if (iat > 0) {
            f->iat_sum     += iat;
            f->iat_sq_sum  += iat * iat;
            f->iat_count++;

            if (f->iat_count == 1) {
                f->iat_min = iat;
                f->iat_max = iat;
            } else {
                if (iat < f->iat_min) f->iat_min = iat;
                if (iat > f->iat_max) f->iat_max = iat;
            }

            /* idle threshold = 1.0 segundo */
            if (iat > 1.0) {
                f->idle_time_total += iat;
                f->idle_count++;
            }
        }

        f->last_seen = ts;
    }

    f->packets++;
    f->bytes += pkt_len;
}

