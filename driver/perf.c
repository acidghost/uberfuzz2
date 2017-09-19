#define _GNU_SOURCE
#include "perf.h"
#include "log.h"

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>


#define PERF_MAP_PG 512
#define PERF_MAP_SZ (getpagesize() * (PERF_MAP_PG + 1))
#define PERF_AUX_PG 1024
#define PERF_AUX_SZ (getpagesize() * PERF_AUX_PG)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define ATOMIC_GET(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define ATOMIC_SET(x, y) __atomic_store_n(&(x), y, __ATOMIC_SEQ_CST)

#if defined(__i386__)
#   define rmb() __asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
#   define mb() __asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
#elif defined(__x86_64)
#   define rmb() __asm volatile("lfence":::"memory")
#   define mb() __asm volatile("mfence":::"memory")
#endif

typedef struct gbl_status {
    pid_t child_pid;
    int perf_fd;
    size_t data_ready;
    void *mmap_buf;
    void *mmap_aux;
} gbl_status_t;

int32_t perf_bts_type = -1;
enum llevel_t log_level = DEBUG;

gbl_status_t gbl_status = {
    -1, -1, 0, NULL, NULL
};


static inline long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                                   int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}


static bool perf_init(void)
{
    int fd = open("/sys/bus/event_source/devices/intel_bts/type", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        PLOG_F("Intel BTS not supported");
        return false;
    }

    char buf[127];
    ssize_t sz = read(fd, buf, 127);
    if (sz < 0) {
        PLOG_F("failed reading BTS type file");
        close(fd);
        return false;
    }

    perf_bts_type = (int32_t) strtoul(buf, NULL, 10);
    LOG_D("perf_bts_type = %" PRIu32, perf_bts_type);

    close(fd);
    return true;
}


static void analyze_bts(bts_branch_t **bts_start, uint64_t *count)
{
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *) gbl_status.mmap_buf;
    uint64_t aux_head = ATOMIC_GET(pem->aux_head);
    rmb();
    bts_branch_t *br = (bts_branch_t *) gbl_status.mmap_aux;

    if (bts_start != NULL && count != NULL) {
        *bts_start = br;
        *count = ((bts_branch_t *)(gbl_status.mmap_aux + aux_head) - br);
        return;
    }

    uint64_t counter = 0;
    for (; br < ((bts_branch_t *)(gbl_status.mmap_aux + aux_head)); br++) {
        if (unlikely(br->from > 0xFFFFFFFF00000000) || unlikely(br->to > 0xFFFFFFFF00000000)) {
            continue;
        }
        LOG_D("[%" PRIu64 "] 0x%x -> 0x%x", counter, br->from, br->to);
        LOG_M("branch,%" PRIu64 ",%" PRIu64, br->from, br->to);
        counter++;
    }

    LOG_I("BTS recorded %" PRIu64 " branches", counter);
}


static void perf_sig_handler(int signum, siginfo_t *siginfo, void *dummy)
{
    if (signum == SIGIO) {
        kill(gbl_status.child_pid, SIGTRAP);
        gbl_status.data_ready++;
    }
}


static int32_t perf_parent(bts_branch_t **bts_start, uint64_t *count)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = perf_sig_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGIO, &sa, NULL) < 0) {
        PLOG_F("error setting up signal handler");
        return PERF_FAILURE;
    }

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    pe.exclude_kernel = 1;
    pe.type = perf_bts_type;

    gbl_status.perf_fd = perf_event_open(&pe, gbl_status.child_pid, -1, -1, 0);
    if (gbl_status.perf_fd == -1) {
        PLOG_F("perf_event_open() failed");
        goto bail_perf_open;
    }

    gbl_status.mmap_buf = mmap(NULL, PERF_MAP_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, gbl_status.perf_fd, 0);
    if (gbl_status.mmap_buf == MAP_FAILED) {
        PLOG_F("failed mmap perf buffer, sz=%zu", (size_t) PERF_MAP_SZ);
        goto bail_perf_buf;
    }

    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *) gbl_status.mmap_buf;
    pem->aux_offset = pem->data_offset + pem->data_size;
    pem->aux_size = PERF_AUX_SZ;
    gbl_status.mmap_aux = mmap(NULL, pem->aux_size, PROT_READ, MAP_SHARED, gbl_status.perf_fd, pem->aux_offset);
    if (gbl_status.mmap_aux == MAP_FAILED) {
        PLOG_F("failed mmap perf aux, sz=%zu", (size_t) PERF_AUX_SZ);
        goto bail_perf_aux;
    }

    fcntl(gbl_status.perf_fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
    fcntl(gbl_status.perf_fd, F_SETSIG, SIGIO);
    fcntl(gbl_status.perf_fd, F_SETOWN, getpid());
    ioctl(gbl_status.perf_fd, PERF_EVENT_IOC_ENABLE, 0);

    int status;
    int wait_ret;
    while (1) {
        LOG_D("waiting for child PID=%lu", gbl_status.child_pid);
        wait_ret = waitpid(gbl_status.child_pid, &status, 0);
        if (wait_ret == -1 && errno == EINTR) {
            continue;
        }
        if (wait_ret == -1) {
            PLOG_F("failed waiting for child PID=%lu", gbl_status.child_pid);
            goto bail_perf_wait;
        }
        if (gbl_status.data_ready > 0) {
            gbl_status.data_ready--;
            analyze_bts(bts_start, count);
        }
        if (WIFEXITED(status)) {
            LOG_D("child terminated with status %d", WEXITSTATUS(status));
            break;
        } else if (WIFSIGNALED(status)) {
            LOG_D("child terminated by signal #%d", WTERMSIG(status));
            break;
        } else if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
            LOG_D("child stopped by signal #%d", WSTOPSIG(status));
            break;
        }
        if (ptrace(PTRACE_CONT, gbl_status.child_pid, 0, 0) == -1) {
            PLOG_F("failed to continue child");
            return PERF_FAILURE;
        }
    }

    analyze_bts(bts_start, count);
    ATOMIC_SET(pem->data_head, 0);
    ATOMIC_SET(pem->data_tail, 0);
    ATOMIC_SET(pem->aux_head, 0);
    ATOMIC_SET(pem->aux_tail, 0);
    return PERF_SUCCESS;

bail_perf_wait:
    munmap(gbl_status.mmap_aux, PERF_AUX_SZ);
bail_perf_aux:
    munmap(gbl_status.mmap_buf, PERF_MAP_SZ);
bail_perf_buf:
    close(gbl_status.perf_fd);
bail_perf_open:
    kill(gbl_status.child_pid, 9);
    return PERF_FAILURE;
}


static int32_t perf_child(char const **argv)
{
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd == -1) {
        PLOG_F("failed to open /dev/null");
        return PERF_FAILURE;
    }
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);

    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        PLOG_F("failed to ptrace child");
        return PERF_FAILURE;
    }

    raise(SIGTRAP);
    execv(argv[0], (char *const *) &argv[0]);
    return PERF_FAILURE;
}


static void perf_close(void)
{
    if (gbl_status.mmap_aux != NULL) {
        munmap(gbl_status.mmap_aux, PERF_AUX_SZ);
        gbl_status.mmap_aux = NULL;
    }
    if (gbl_status.mmap_buf != NULL) {
        munmap(gbl_status.mmap_buf, PERF_MAP_SZ);
        gbl_status.mmap_buf = NULL;
    }
    if (gbl_status.perf_fd != -1) {
        close(gbl_status.perf_fd);
        gbl_status.perf_fd = -1;
    }
}


void perf_monitor(char const **argv)
{
    perf_close();
    if (!perf_init()) {
        exit(EXIT_FAILURE);
    }

    gbl_status.child_pid = fork();
    if (gbl_status.child_pid < 0) {
        PLOG_F("failed to fork");
        exit(EXIT_FAILURE);
    } else if (gbl_status.child_pid > 0) {
        if (perf_parent(NULL, NULL) == PERF_FAILURE)
          exit(EXIT_FAILURE);
    } else {
        if (perf_child(argv) == PERF_FAILURE)
          exit(EXIT_FAILURE);
    }
}


int32_t perf_monitor_api(const uint8_t *data, size_t data_count, char const **argv,
                         bts_branch_t **bts_start, uint64_t *count)
{
    perf_close();
    if (!perf_init()) {
        return PERF_FAILURE;
    }

    int in_fd = open("./.input", O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (in_fd == -1) {
        PLOG_F("failed to open input file");
        return PERF_FAILURE;
    }
    ssize_t write_sz = write(in_fd, data, data_count);
    if (write_sz == -1) {
        PLOG_F("failed to write to input file");
        close(in_fd);
        unlink("./.input");
        return PERF_FAILURE;
    }
    close(in_fd);

    gbl_status.child_pid = fork();
    if (gbl_status.child_pid < 0) {
        PLOG_F("failed to fork");
        unlink("./.input");
        return PERF_FAILURE;
    } else if (gbl_status.child_pid > 0) {
        close(in_fd);
        int32_t ret = perf_parent(bts_start, count);
        unlink("./.input");
        return ret;
    } else {
        in_fd = open("./.input", O_RDONLY);
        if (in_fd == -1) {
            PLOG_F("failed to open input file");
            return PERF_FAILURE;
        }
        dup2(in_fd, STDIN_FILENO);
        close(in_fd);
        perf_child(argv);
        LOG_M("returning from child...");
        // raise(SIGKILL);
        return 0;
        // kill(getpid(), 9);
        // _exit(1);
        // abort();
    }
}
