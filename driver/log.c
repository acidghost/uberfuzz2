#include "log.h"
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>


void log_log(enum llevel_t ll, const char *fn, int ln, bool perr, const char *fmt, ...)
{
    char strerr[512];
    if (perr == true) {
        snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
    }
    struct ll_t {
        const char *descr;
        const char *prefix;
        const bool print_funcline;
    };
    static const struct ll_t log_levels[] = {
        {NULL, NULL, false},
        {"F", "\033[7;35m", true},
        {"E", "\033[1;31m", true},
        {"W", "\033[0;33m", true},
        {"I", "\033[1m", false},
        {"D", "\033[0;4m", true},
    };

    if (log_levels[ll].descr) {
        dprintf(STDOUT_FILENO, "[%s] ", log_levels[ll].descr);
    }

    if (log_levels[ll].print_funcline) {
        dprintf(STDOUT_FILENO, "%s():%d ", fn, ln);
    }

    va_list args;
    va_start(args, fmt);
    vdprintf(STDOUT_FILENO, fmt, args);
    va_end(args);

    if (perr == true) {
        dprintf(STDOUT_FILENO, ": %s", strerr);
    }

    dprintf(STDOUT_FILENO, "\n");
}
