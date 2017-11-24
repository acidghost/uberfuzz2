#define _GNU_SOURCE

#include "inotify.h"
#include "log.h"

#include <sys/inotify.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#define IN_EVENT_SIZE       (sizeof(struct inotify_event) + NAME_MAX + 1)
#define IN_EVENT_BUF_SIZE   (IN_EVENT_SIZE * 64)


static struct inotify_event *
inotify_event_new(void)
{
    struct inotify_event *in_event = malloc(IN_EVENT_BUF_SIZE);
    assert(in_event != NULL);
    return in_event;
}


static int
inotify_wait4_creation(int inotify_fd, const char *path, const bool *keep_running)
{
    char *parent_path = strdup(path);
    char *last_slash = strrchr(parent_path, '/');
    if (last_slash == NULL) {
        LOG_F("failed to find a '/' in %s while waiting for parent creation", parent_path);
        free(parent_path);
        return -1;
    }
    *last_slash = '\0';

    int wd = inotify_add_watch(inotify_fd, parent_path, IN_CREATE);
    if (wd == -1) {
        PLOG_F("failed to add inotify watch to %s", parent_path);
        free(parent_path);
        return -1;
    }

    struct inotify_event *in_event = inotify_event_new();
    while (*keep_running) {
        ssize_t ret = read(inotify_fd, in_event, IN_EVENT_SIZE);
        if (ret == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100);
                continue;
            }
            break;
        }

        if ((in_event->mask & IN_CREATE) == IN_CREATE &&
            strstr(in_event->name, last_slash + 1) != NULL) {
            break;
        }
    }
    free(in_event);

    int ret = 0;
    if (inotify_rm_watch(inotify_fd, wd) == -1) {
        PLOG_F("failed to remove inotify watch for %s", parent_path);
        ret = -1;
    }
    free(parent_path);
    return ret;
}


int
inotify_setup(const char *path, const bool *keep_running, int *watch_d)
{
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd == -1) {
        PLOG_F("failed to init inotify");
        return -1;
    }

    int wd = 0;
    while (*keep_running) {
        wd = inotify_add_watch(inotify_fd, path, IN_CLOSE_WRITE | IN_DELETE_SELF);
        if (wd == -1) {
            if (errno == ENOENT) {
                if (inotify_wait4_creation(inotify_fd, path, keep_running) == -1) {
                    return -1;
                }
                continue;
            }
            PLOG_F("failed to add inotify watch for %s", path);
            return -1;
        }
        break;
    }

    *watch_d = wd;
    return inotify_fd;
}


static bool
inotify_process_event(int wd, const char *path,
                      const struct inotify_event *in_event, const char **name)
{
    if (in_event->wd != wd) {
        return true;
    }

    if ((in_event->mask & IN_DELETE_SELF) == IN_DELETE_SELF) {
        LOG_E("corpus directory %s deleted", path);
        return false;
    }

    if (in_event->len == 0) {
        LOG_W("inotify event name len is zero (%" PRIx32 ")", in_event->mask);
        return true;
    }

    *name = in_event->name;
    return true;
}


bool
inotify_maybe_read(int inotify_fd, int wd, const char *path, HashSet *seen,
                   char **names, size_t *names_len)
{
    struct inotify_event *in_event_mem = inotify_event_new();

    ssize_t ret = read(inotify_fd, in_event_mem, IN_EVENT_BUF_SIZE);
    if (ret == -1) {
        free(in_event_mem);
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return true;
        return false;
    }

    size_t names_i = 0, in_event_i = 0, in_event_offset = 0;
    while (in_event_offset < ret) {
        const char *ptr = ((char *) in_event_mem) + in_event_offset;
        const struct inotify_event *in_event = (struct inotify_event*) ptr;
        const char *filename = NULL;
        if (inotify_process_event(wd, path, in_event, &filename) == false) {
            free(in_event_mem);
            return false;
        }

        if (filename != NULL) {
            if (names_i >= IN_NAMES_MAX) {
                LOG_W("exceeded IN_NAMES_MAX (%d)", IN_NAMES_MAX);
                free(in_event_mem);
                return false;
            }

            char *file_path = malloc(PATH_MAX * sizeof(char));
            snprintf(file_path, PATH_MAX - 1, "%s/%s", path, filename);
            file_path = realloc(file_path, strlen(file_path) + 1);

            if (hashset_contains(seen, file_path)) {
                free(file_path);
            } else if (hashset_add(seen, file_path) != CC_OK) {
                LOG_W("failed to add %s to seen hashset", file_path);
                free(file_path);
                free(in_event_mem);
                return false;
            } else {
                names[names_i] = file_path;
                names_i++;
            }
        }

        in_event_i++;
        in_event_offset += sizeof(struct inotify_event) + in_event->len;
    }

    LOG_D("got %zu inotify events on %s", in_event_i, path);

    *names_len = names_i;
    free(in_event_mem);
    return true;
}
