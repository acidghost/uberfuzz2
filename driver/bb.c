#include "bb.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LINE_SZ         1024
#define BBS_MAX_N       10240
#define BBS_SZ          (BBS_MAX_N * sizeof(basic_block_t))


ssize_t basic_blocks_find(const char *r2bb_script, const char *bin, basic_block_t **bbs)
{
    const size_t r2bb_script_len = strlen(r2bb_script);
    const size_t script_len = r2bb_script_len + strlen(bin) + 2;
    char script[script_len];
    strcpy(script, r2bb_script);
    script[r2bb_script_len] = ' ';
    strcpy(script + r2bb_script_len + 1, bin);
    script[script_len-1] = '\0';

    FILE *stream = popen(script, "r");
    assert(stream != NULL);

    char line[LINE_SZ];
    *bbs = malloc(BBS_SZ);
    assert(*bbs != NULL);
    memset(*bbs, 0, BBS_SZ);
    size_t bbs_n = 0;
    while (fgets(line, LINE_SZ, stream) != NULL) {
        assert(bbs_n < BBS_MAX_N);
        char *col = strtok(line, " ");
        uint8_t col_idx = 0;
        while (col != NULL) {
            long value = atol(col);
            switch (col_idx) {
            case 0:
                (*bbs)[bbs_n].from = value;
                break;
            case 1:
                (*bbs)[bbs_n].to = value;
                break;
            case 2:
                break;
            default:
                assert(0);
            }
            col = strtok(NULL, " ");
            col_idx++;
        }
        bbs_n++;
    }
    pclose(stream);

    *bbs = realloc(*bbs, bbs_n * sizeof(basic_block_t));
    assert(*bbs != NULL);

    return bbs_n;
}
