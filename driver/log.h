#ifndef _LOG_H
#define _LOG_H

#include <stdbool.h>

enum llevel_t {
    MACHINE = 0,
    FATAL,
    ERROR,
    WARNING,
    INFO,
    DEBUG
};

extern enum llevel_t log_level;

#define LOG_D(...) if (log_level >= DEBUG) { log_log(DEBUG, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_I(...) if (log_level >= INFO) { log_log(INFO, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_W(...) if (log_level >= WARNING) { log_log(WARNING, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_E(...) if (log_level >= ERROR) { log_log(ERROR, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_F(...) if (log_level >= FATAL) { log_log(FATAL, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_M(...) if (log_level == MACHINE) { log_log(MACHINE, __FUNCTION__, __LINE__, false, __VA_ARGS__); }

#define PLOG_D(...) if (log_level >= DEBUG) { log_log(DEBUG, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_I(...) if (log_level >= INFO) { log_log(INFO, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_W(...) if (log_level >= WARNING) { log_log(WARNING, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_E(...) if (log_level >= ERROR) { log_log(ERROR, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_F(...) if (log_level >= FATAL) { log_log(FATAL, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_M(...) LOG_M(__VA_ARGS__)

void log_log(enum llevel_t ll, const char *fn, int ln, bool perr, const char *fmt, ...);

#endif
