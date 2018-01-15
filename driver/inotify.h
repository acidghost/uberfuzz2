#ifndef _INOTIFY_H_
#define _INOTIFY_H_

#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <collectc/hashset.h>


#define IN_NAMES_MAX            127


int inotify_setup(const char *path, const bool *keep_running, int *watch_d);
bool inotify_maybe_read(int inotify_fd, int wd, const char *path,
                        HashSet *seen, char **names, size_t *names_len);

#endif
