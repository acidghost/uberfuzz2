#ifndef _PERF_H
#define _PERF_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>

#define PERF_FAILURE -1
#define PERF_SUCCESS  1

typedef struct bts_branch {
    uint64_t from;
    uint64_t to;
    uint64_t misc;
} bts_branch_t;

void perf_monitor(char const **argv);
int32_t perf_monitor_api(const uint8_t *data, size_t data_count, char const **argv,
                         const char *input_filename, const bool use_stdin,
                         bts_branch_t **bts_start, uint64_t *count);

void perf_close(void);

#endif
