#ifndef _BB_H_
#define _BB_H_

#define _GNU_SOURCE
#include <inttypes.h>
#include <unistd.h>

typedef struct basic_block {
    uint64_t from;
    uint64_t to;
} basic_block_t;

ssize_t basic_blocks_find(const char *r2bb_script, const char *bin, basic_block_t **bbs);

#endif
