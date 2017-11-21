#ifndef _INOTIFY_H_
#define _INOTIFY_H_

#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <collectc/hashset.h>


int inotify_setup(const char *path, const bool *keep_running, int *watch_d);
int inotify_maybe_read(int inotify_fd, int wd, const char *path,
                       HashSet *seen, uint8_t *buf, size_t buf_len);

#endif
