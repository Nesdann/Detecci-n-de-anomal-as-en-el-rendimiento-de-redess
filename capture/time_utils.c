#include "time_utils.h"

double timeval_diff(struct timeval a, struct timeval b)
{
    return (a.tv_sec - b.tv_sec) +
           (a.tv_usec - b.tv_usec) / 1e6;
}
