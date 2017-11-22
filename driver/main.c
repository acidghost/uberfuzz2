#define _GNU_SOURCE

#include "log.h"
#include "perf.h"
#include "sections.h"
#include "bb.h"
#include "inotify.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <zmq.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <collectc/hashtable.h>
#include <collectc/hashset.h>
#include <libgen.h>
#include <time.h>


typedef struct driver {
    const char *fuzzer_id;
    char **fuzzer;
    size_t fuzzer_n;
    pid_t fuzzer_pid;
    const char **sut;
    const char *sut_input_file;
    bool sut_use_stdin;
    const char *fuzzer_log_filename;
    const char *fuzzer_log_err_filename;
    const char *fuzzer_corpus_path;
    section_bounds_t *sec_bounds;
    basic_block_t *bbs;
    size_t bbs_n;
    size_t input_n;
    void *interesting_push;
    void *use_sub;
    void *metric_rep;
    const char *data_path;
    const char *inject_path;
    size_t injected_n;
    HashTable *coverage_info;
    bool single_mode;
    struct timespec start_time;
    ssize_t interesting_log_fd;
    ssize_t coverage_log_fd;
    HashSet *interesting_seen;
} driver_t;


typedef struct branch {
    uint64_t from;
    uint64_t to;
} branch_t;


typedef float (*metric_fn_t)(driver_t *, branch_t *, size_t);


#define BUF_SZ              (1024 * 1024)
#define RECV_BUF_SZ         (1024)
#define HASH_KEY_SEP        "/"
#define HASH_KEY_SZ         64
#define COV_FMT             "id:%05zu.%zu.coverage"
#define INPUT_FMT           "id:%05zu.input"
#define METRIC_FN           &metric_diff
#define SUB_TOPIC           "A"
#define MAX_FUZZERS         16
#define MAX_FUZZER_ID       16
#define USE_FUZZ_ID_SEP     "_"
#define WORK_PATH           "./work"        // TODO: make it a cmd line option?

#if !defined(LOG_LEVEL)
#define LOG_LEVEL           INFO
#endif


bool keep_running = true;


static uint64_t
get_delta_micro(struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    return (now.tv_sec - start->tv_sec) * 1000000 + (now.tv_nsec - start->tv_nsec) / 1000;
}


static pid_t
start_fuzzer(driver_t *driver)
{
    pid_t pid = fork();
    if (pid < 0) {
        PLOG_F("failed to fork");
        return -1;
    } else if (pid == 0) {
        // child, run fuzzer
        const char *filename = driver->fuzzer_log_filename == NULL ?
                                "/dev/null" : driver->fuzzer_log_filename;

        int fd = driver->fuzzer_log_filename == NULL ?
                open(filename, O_WRONLY) :
                open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (fd == -1) {
            PLOG_F("failed to open %s", filename);
            abort();
        }

        const char *err_filename = driver->fuzzer_log_err_filename == NULL ?
                                    "/dev/null" : driver->fuzzer_log_err_filename;

        int err_fd = driver->fuzzer_log_err_filename == NULL ?
                    open(err_filename, O_WRONLY) :
                    open(err_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (err_fd == -1) {
            PLOG_F("failed to open %s", err_filename);
            abort();
        }

        dup2(fd, STDOUT_FILENO);
        dup2(err_fd, STDERR_FILENO);

        execv(driver->fuzzer[0], driver->fuzzer);
        PLOG_F("failed to execv fuzzer");
        abort();
    } else {
        // parent, child_pid = pid
        return pid;
    }
}


static inline char *
coverage_info_key(branch_t *branch)
{
    char *key = malloc(sizeof(char) * HASH_KEY_SZ);
    assert(key != NULL);
    snprintf(key, HASH_KEY_SZ - 1, "%" PRIu64 HASH_KEY_SEP "%" PRIu64,
             branch->from, branch->to);
    return key;
}


static ssize_t
add_coverage_info(driver_t *driver, branch_t *coverage_info, size_t count)
{
    ssize_t added_unique_branches = 0;
    for (size_t i = 0; i < count; i++) {
        branch_t branch = coverage_info[i];
        char *key = coverage_info_key(&branch);

        uint64_t *value = NULL;
        if (hashtable_get(driver->coverage_info, key, (void **) &value) == CC_OK) {
            (*value)++;
            free(key);
        } else {
            value = malloc(sizeof(uint64_t));
            assert(value != NULL);
            *value = 1;
            added_unique_branches++;
            if (hashtable_add(driver->coverage_info, key, value) != CC_OK) {
                LOG_F("failed to add branch [%s]", key);
                return -1;
            }
        }
    }

    return added_unique_branches;
}


static bool
process_interesting_input(driver_t *driver, uint8_t *buf, size_t size)
{
    // collect coverage info, filter it and add to knowledge-base
    bts_branch_t *bts_start;
    uint64_t count;
    int perf_ret = perf_monitor_api(buf, size, driver->sut, driver->sut_input_file,
                                    driver->sut_use_stdin, &bts_start, &count);
    if (perf_ret == PERF_FAILURE) {
        LOG_F("failed perf monitoring");
        return false;
    }

    const section_bounds_t *sec_bounds = driver->sec_bounds;
    const uint64_t sec_start = sec_bounds ? sec_bounds->sec_start : 0;
    const uint64_t sec_end = sec_bounds ? sec_bounds->sec_end : 0;

    branch_t *branches = malloc(sizeof(branch_t) * count);
    assert(branches != NULL);
    size_t branches_i = 0;
    for (uint64_t i = 0; i < count; i++) {
        bts_branch_t branch = bts_start[i];
        if (branch.from > 0xFFFFFFFF00000000 || branch.to > 0xFFFFFFFF00000000) {
            continue;
        }

        if (sec_bounds && (
                (branch.from < sec_start || branch.from > sec_end)
                || (branch.to < sec_start || branch.to > sec_end)
            )
        ) continue;

        uint64_t from_bb = 0, to_bb = 0;
        for (size_t j = 0; j < driver->bbs_n; j++) {
            basic_block_t bb = driver->bbs[j];
            if (branch.from >= bb.from && branch.from < bb.to)
                from_bb = bb.from;
            if (branch.to >= bb.from && branch.to < bb.to)
                to_bb = bb.from;
            if (from_bb != 0 && to_bb != 0)
                break;
        }
        if (from_bb == 0)
            from_bb = branch.from;
        if (to_bb == 0)
            to_bb = branch.to;

        branches[branches_i] = (branch_t) { from_bb, to_bb };
        branches_i++;
    }

    ssize_t new_branches = add_coverage_info(driver, branches, branches_i);
    if (new_branches == -1) {
        LOG_F("failed to add coverage info");
        return false;
    }

    // store coverage info to file
    char coverage_filename[PATH_MAX];
    snprintf(coverage_filename, PATH_MAX - 1, "%s/" COV_FMT,
             driver->data_path, driver->input_n, branches_i);

    FILE *coverage_file = fopen(coverage_filename, "wb");
    if (coverage_file == NULL) {
        PLOG_F("failed to open coverage file %s", coverage_filename);
        return false;
    }
    if (fwrite(branches, sizeof(branch_t), branches_i, coverage_file) != branches_i) {
        LOG_E("items written to %s do not match", coverage_filename);
        fclose(coverage_file);
        return false;
    }
    fflush(coverage_file);
    fclose(coverage_file);
    free(branches);

    // store input to file
    char input_filename[PATH_MAX];
    snprintf(input_filename, PATH_MAX - 1, "%s/" INPUT_FMT,
             driver->data_path, driver->input_n);

    FILE *input_file = fopen(input_filename, "w");
    if (input_file == NULL) {
        PLOG_F("failed to open input file %s", input_filename);
        return false;
    }
    if (fwrite(buf, sizeof(uint8_t), size, input_file) != size) {
        LOG_E("items written to %s do not match", input_filename);
        fclose(input_file);
        return false;
    }
    fflush(input_file);
    fclose(input_file);

    if (driver->single_mode) {
        uint64_t delta_time = get_delta_micro(&driver->start_time);
        char line[PATH_MAX];
        // log to interesting log file
        snprintf(line, PATH_MAX - 1, "%" PRIu64 " %zu\n",
            delta_time, driver->input_n);
        if (write(driver->interesting_log_fd, line, strlen(line)) == -1) {
            PLOG_F("failed to write to interesting log file");
            return false;
        }
        // log to coverage log file
        HashTableIter hti;
        hashtable_iter_init(&hti, driver->coverage_info);
        TableEntry *entry = NULL;
        size_t branch_hits = 0;
        while (hashtable_iter_next(&hti, &entry) != CC_ITER_END)
            branch_hits += *((uint64_t *) entry->value);
        snprintf(line, PATH_MAX - 1, "%" PRIu64 " %zu %zu %zu\n",
            delta_time, hashtable_size(driver->coverage_info),
            new_branches, branch_hits);
        if (write(driver->coverage_log_fd, line, strlen(line)) == -1) {
            PLOG_F("failed to write to coverage log file");
            return false;
        }
    } else {
        // send zmq message
        char message[PATH_MAX * 2];
        snprintf(message, (PATH_MAX * 2) - 1, "%s %s %s",
                 driver->fuzzer_id, input_filename, coverage_filename);
        if (zmq_send(driver->interesting_push, message, strlen(message), 0) == -1) {
            PLOG_F("failed pushing on the interesting queue");
            return false;
        }
    }

    return true;
}


static ssize_t
load_coverage_info(const char *cov_filename, branch_t **cov_info)
{
    assert(cov_info != NULL);

    // parse cov_count from filename
    char *cov_filename_dup = strdup(cov_filename);
    char *cov_basename = basename(cov_filename_dup);
    size_t cov_count = 0, input_n = 0;
    sscanf(cov_basename, COV_FMT, &input_n, &cov_count);
    free(cov_filename_dup);

    FILE *cov_file = fopen(cov_filename, "rb");
    if (cov_file == NULL) {
        PLOG_F("failed to open %s", cov_filename);
        return -1;
    }

    *cov_info = malloc(sizeof(branch_t) * cov_count);
    assert(*cov_info != NULL);
    size_t r = fread(*cov_info, sizeof(branch_t), cov_count, cov_file);

    ssize_t ret = cov_count;
    if (ferror(cov_file) != 0 || r != cov_count)
        ret = -1;

    fclose(cov_file);
    return ret;
}


static float
metric_diff(driver_t *driver, branch_t *cov_info, size_t cov_count)
{
    float score = 0;
    for (size_t i = 0; i < cov_count; i++) {
        branch_t branch = cov_info[i];
        char *key = coverage_info_key(&branch);
        if (!hashtable_contains_key(driver->coverage_info, key)) {
            score++;
        }
        free(key);
    }

    return score;
}


static bool
compute_metric(driver_t *driver, const char *cov_filename, metric_fn_t f, float *score)
{
    assert(score != NULL);

    branch_t *cov_info = NULL;
    ssize_t cov_count = load_coverage_info(cov_filename, &cov_info);
    if (cov_count < 0) {
        return false;
    }

    *score = f(driver, cov_info, cov_count);
    free(cov_info);

    return true;
}


static bool
inject_into_fuzzer(driver_t *driver, const char *input_path)
{
    int input_fd = open(input_path, O_RDONLY);
    if (input_fd == -1) {
        PLOG_F("failed to open file to read %s", input_path);
        return false;
    }

    char *injected_filename = malloc(PATH_MAX * sizeof(char));
    assert(injected_filename != NULL);
    snprintf(injected_filename, PATH_MAX - 1, "%s/" INPUT_FMT,
        driver->inject_path, driver->injected_n);
    injected_filename = realloc(injected_filename, strlen(injected_filename) + 1);

    int injected_fd = open(injected_filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (injected_fd == -1) {
        PLOG_F("failed to open file to write %s", injected_filename);
        close(input_fd);
        return false;
    }

    uint8_t buf[BUF_SZ];
    while (1) {
        ssize_t read_res = read(input_fd, buf, sizeof(buf));
        if (read_res == 0) {
            break;
        } else if (read_res == -1) {
            PLOG_F("failed to read from %s", input_path);
            close(input_fd);
            close(injected_fd);
            return false;
        }

        int write_res = write(injected_fd, buf, read_res);
        if (write_res != read_res) {
            if (write_res == -1) {
                PLOG_F("failed to write to %s", injected_filename);
            } else {
                LOG_F("failed to write to %s (written != read)", injected_filename);
            }

            close(input_fd);
            close(injected_fd);
            return false;
        }
    }

    close(input_fd);
    close(injected_fd);

    driver->injected_n++;

    if (hashset_add(driver->interesting_seen, injected_filename) != CC_OK) {
        LOG_W("failed to add %s to seen inputs hashset", injected_filename);
    }

    return true;
}


static bool
use_input(driver_t *driver, const char *input_path, const char *coverage_path)
{
    branch_t *cov_info = NULL;
    ssize_t cov_count = load_coverage_info(coverage_path, &cov_info);
    if (cov_count < 0) {
        LOG_F("failed to read coverage info from %s", coverage_path);
        return false;
    }

    bool coverage_added = add_coverage_info(driver, cov_info, cov_count) != -1;
    free(cov_info);

    if (!coverage_added) {
        LOG_F("failed to add coverage info from %s", coverage_path);
        return false;
    }

    if (!inject_into_fuzzer(driver, input_path)) {
        LOG_E("failed to inject into fuzzer");
        return false;
    }

    return true;
}


static int
driver_loop(driver_t *driver)
{
    int ret = EXIT_SUCCESS;
    driver->fuzzer_pid = start_fuzzer(driver);
    if (driver->fuzzer_pid == -1) {
        LOG_F("failed to start fuzzer %s", driver->fuzzer[0]);
        return EXIT_FAILURE;
    }
    LOG_I("fuzzer %s started (pid=%d)", driver->fuzzer[0], driver->fuzzer_pid);
    clock_gettime(CLOCK_MONOTONIC_RAW, &driver->start_time);

    int watch_d = 0;
    int inotify_fd = inotify_setup(driver->fuzzer_corpus_path, &keep_running, &watch_d);
    if (inotify_fd == -1) {
        LOG_F("failed to setup inotify on %s", driver->fuzzer_corpus_path);
        return EXIT_FAILURE;
    }

    while (keep_running) {
        if (kill(driver->fuzzer_pid, 0) == -1 && errno == ESRCH) {
            LOG_I("fuzzer stopped, exiting");
            break;
        }

        if (!keep_running) {
            if (kill(driver->fuzzer_pid, SIGKILL) == -1) {
                PLOG_F("failed to kill fuzzer (pid=%d)", driver->fuzzer_pid);
                ret = EXIT_FAILURE;
            }
            break;
        }

        // 1. look if fuzzer has a new input -> process it
        uint8_t buf[BUF_SZ];
        int size = inotify_maybe_read(inotify_fd, watch_d, driver->fuzzer_corpus_path,
                                      driver->interesting_seen, buf, BUF_SZ);
        if (size == -1) {
            ret = EXIT_FAILURE;
            break;
        } else if (size > 0) {
            driver->input_n++;
            // analyse new input and push to `interesting_push`
            // FIXME: why is the following line required?
            LOG_I("got input %zu of %zu bytes", driver->input_n, size);
            if (!process_interesting_input(driver, buf, size)) {
                LOG_F("failed processing interesting input");
                ret = EXIT_FAILURE;
                break;
            }
        }
        usleep(100);

        uint8_t zmq_recv_buf[RECV_BUF_SZ];
        memset(zmq_recv_buf, 0, RECV_BUF_SZ);

        if (!driver->single_mode) {
            // 2. look for metric requests -> reply to request
            size = zmq_recv(driver->metric_rep, zmq_recv_buf, RECV_BUF_SZ-1, ZMQ_DONTWAIT);
            if (size == -1) {
                if (errno != EAGAIN && errno != EFSM) {
                    PLOG_F("failed receiving on the metric queue");
                    ret = EXIT_FAILURE;
                    break;
                }
            } else {
                zmq_recv_buf[size] = '\0';
                LOG_I("metric req %s", zmq_recv_buf);
                float metric = 0;
                if (!compute_metric(driver, (const char *) zmq_recv_buf, METRIC_FN, &metric)) {
                    LOG_F("failed to compute metric");
                    ret = EXIT_FAILURE;
                    break;
                }
                LOG_I("computed metric %f", metric);

                char zmq_send_buf[RECV_BUF_SZ];
                snprintf(zmq_send_buf, RECV_BUF_SZ, "%f", metric);
                int r = zmq_send(driver->metric_rep, zmq_send_buf, strlen(zmq_send_buf), 0);
                if (r == -1) {
                    PLOG_F("failed to send metric reply");
                    ret = EXIT_FAILURE;
                    break;
                }
            }

            memset(zmq_recv_buf, 0, RECV_BUF_SZ);
            usleep(100);


            // 3. look for new inputs to use/fuzz -> inject into fuzzer
            size = zmq_recv(driver->use_sub, zmq_recv_buf, RECV_BUF_SZ-1, ZMQ_DONTWAIT);
            if (size == -1) {
                if (errno != EAGAIN) {
                    PLOG_F("failed receiving on the use queue");
                    ret = EXIT_FAILURE;
                    break;
                }
            } else {
                zmq_recv_buf[size] = '\0';
                // parse 'use' message
                char fuzzer_ids_str[MAX_FUZZERS * MAX_FUZZER_ID];
                char input_path[PATH_MAX], coverage_path[PATH_MAX];
                sscanf((char *) zmq_recv_buf, SUB_TOPIC " %s %s %s",
                    fuzzer_ids_str, input_path, coverage_path);

                // parse fuzzer ids
                char *fuzzer_id = strtok(fuzzer_ids_str, USE_FUZZ_ID_SEP);
                bool use_it = false;
                while (fuzzer_id != NULL) {
                    if (strcmp(fuzzer_id, driver->fuzzer_id) == 0) {
                        use_it = true;
                        break;
                    }
                    fuzzer_id = strtok(NULL, USE_FUZZ_ID_SEP);
                }

                if (use_it) {
                    LOG_I("using %s", input_path);
                    if (!use_input(driver, input_path, coverage_path)) {
                        LOG_F("failed to use input");
                        ret = EXIT_FAILURE;
                        break;
                    }
                }
            }

            usleep(100);
        }
    }

    close(inotify_fd);
    return ret;
}


void
sig_handler(int signum)
{
    keep_running = false;
}


static bool
parse_fuzzer_cmd(driver_t *driver, const char *fuzzer_cmd_filename)
{
    driver->fuzzer = malloc(sizeof(char *) * 32);
    assert(driver->fuzzer != NULL);

    FILE *f = fopen(fuzzer_cmd_filename, "r");
    if (f == NULL) {
        PLOG_F("failed to open fuzzer config file %s", fuzzer_cmd_filename);
        return false;
    }

    char buf[PATH_MAX];
    size_t i = 0;
    while (fgets(buf, PATH_MAX - 1, f) != NULL) {
        size_t len = strlen(buf) - 1;                   // skip newline
        buf[len] = '\0';
        driver->fuzzer[i] = malloc(sizeof(char) * (len + 1));
        assert(driver->fuzzer[i] != NULL);
        strncpy(driver->fuzzer[i], buf, len + 1);
        i++;
    }

    fclose(f);

    driver->fuzzer_n = i;
    driver->fuzzer[i] = NULL;
    driver->fuzzer = realloc(driver->fuzzer, (i + 1) * sizeof(char *));

    if (i > 1) {
        return true;
    } else {
        LOG_E("only %zd elements in %s", i, fuzzer_cmd_filename);
        return false;
    }
}


static void
free_driver(driver_t *driver)
{
    if (driver->fuzzer) {
        for (size_t i = 0; i < driver->fuzzer_n; i++)
            free(driver->fuzzer[i]);
        free(driver->fuzzer);
    }

    if (driver->sec_bounds)
        free(driver->sec_bounds);
    if (driver->bbs)
        free(driver->bbs);

    if (driver->interesting_push)
        zmq_close(driver->interesting_push);
    if (driver->use_sub)
        zmq_close(driver->use_sub);
    if (driver->metric_rep)
        zmq_close(driver->metric_rep);

    if (driver->coverage_info) {
        HashTableIter hti;
        hashtable_iter_init(&hti, driver->coverage_info);
        TableEntry *entry = NULL;
        while (hashtable_iter_next(&hti, &entry) != CC_ITER_END) {
            free(entry->key);
            free(entry->value);
        }
        hashtable_destroy(driver->coverage_info);
    }

    if (driver->interesting_seen) {
        HashSetIter hsi;
        hashset_iter_init(&hsi, driver->interesting_seen);
        void *entry = NULL;
        while (hashset_iter_next(&hsi, &entry) != CC_ITER_END) {
            free(entry);
        }
        hashset_destroy(driver->interesting_seen);
    }

    if (driver->interesting_log_fd != -1)
        close(driver->interesting_log_fd);

    if (driver->coverage_log_fd != -1)
        close(driver->coverage_log_fd);

    if (driver->fuzzer_pid > 0 && kill(driver->fuzzer_pid, SIGKILL) == -1) {
        PLOG_W("failed to kill fuzzer (pid=%d)", driver->fuzzer_pid);
    }

    free(driver);
}


static void
usage(const char *progname)
{
    printf("usage: %s [options] -- command [args]\n\n"
           "OPTIONS:\n"
           "\t-i fuzzer_id\n\t-f fuzzer_cmd\n\t-b r2bb.sh\n\t-c corpus\n"
           "\t-d data_path\n\t[-l fuzzer_log]\n\t[-L fuzzer_error_log]\n"
           "\t[-s .section]\n"
           "\t[-F input_filename]         (if SUT reads from a file)\n"
           "\t[-p i,u,m -j inject_path]   (those are mandatory in multi mode)\n",
           progname);
}


int
main(int argc, char const *argv[]) {
    log_level = LOG_LEVEL;
    char *sec_name = NULL;
    char *basic_block_script = NULL;
    char *queues_ports_str = NULL;

    driver_t *driver = malloc(sizeof(driver_t));
    assert(driver != NULL);
    memset(driver, 0, sizeof(driver_t));
    driver->sut_use_stdin = true;
    driver->interesting_log_fd = -1;
    driver->coverage_log_fd = -1;

    int opt;
    while ((opt = getopt(argc, (char * const*) argv, "i:f:s:b:c:p:d:l:L:j:F:")) != -1) {
        switch (opt) {
        case 'i':
            driver->fuzzer_id = optarg;
            break;
        case 'f':
            if (!parse_fuzzer_cmd(driver, optarg)) {
                free_driver(driver);
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            sec_name = optarg;
            break;
        case 'b':
            basic_block_script = optarg;
            break;
        case 'c':
            driver->fuzzer_corpus_path = optarg;
            break;
        case 'p':
            queues_ports_str = optarg;
            break;
        case 'd':
            driver->data_path = optarg;
            break;
        case 'l':
            driver->fuzzer_log_filename = optarg;
            break;
        case 'L':
            driver->fuzzer_log_err_filename = optarg;
            break;
        case 'j':
            driver->inject_path = optarg;
            break;
        case 'F':
            driver->sut_input_file = optarg;
            driver->sut_use_stdin = false;
            break;
        }
    }

    if (argc == optind || driver->fuzzer_id == NULL ||
        basic_block_script == NULL || driver->fuzzer_corpus_path == NULL ||
        driver->data_path == NULL)
    {
        free_driver(driver);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (queues_ports_str == NULL || driver->inject_path == NULL) {
        driver->single_mode = true;
    }

    if (driver->sut_use_stdin) {
        char *tmp = malloc(PATH_MAX * sizeof(char));
        snprintf(tmp, PATH_MAX - 1, "%s/.%s.input", WORK_PATH, driver->fuzzer_id);
        driver->sut_input_file = tmp;
    }

    driver->sut = argv + optind;
    size_t sut_length = argc - optind;

    LOG_I("driver on %s (%s mode)", driver->fuzzer[0],
        driver->single_mode ? "single" : "multi");

    char sut_line[PATH_MAX] = { '\0' };
    for (size_t i = 0; i < sut_length; i++) {
        const char *sut_chunk = driver->sut[i];
        char *sut_line_dup = strdup(sut_line);
        snprintf(sut_line, PATH_MAX - 1, "%s %s",
            sut_line_dup[0] == '\0' ? "" : sut_line_dup, sut_chunk);
        free(sut_line_dup);
    }
    LOG_I("SUT:%s", sut_line);

    if (sec_name) {
        driver->sec_bounds = malloc(sizeof(section_bounds_t));
        assert(driver->sec_bounds != NULL);
        int64_t sec_size = section_find(driver->sut[0], sec_name, driver->sec_bounds);
        if (sec_size <= 0) {
            if (sec_size == 0)
                LOG_W("%s has no %s section or it's empty", driver->sut[0], sec_name);
            free_driver(driver);
            exit(EXIT_FAILURE);
        }

        LOG_I("%s 0x%" PRIx64 " 0x%" PRIx64 " %" PRIi64,
            sec_name, driver->sec_bounds->sec_start,
            driver->sec_bounds->sec_end, sec_size);
    } else {
        LOG_I("all code");
    }

    driver->bbs_n = basic_blocks_find(basic_block_script, driver->sut[0], &driver->bbs);
    if (driver->bbs_n < 0) {
        LOG_F("failed reading basic blocks");
        free_driver(driver);
        exit(EXIT_FAILURE);
    }
    LOG_I("found %zd basic blocks", driver->bbs_n);
    for (size_t i = 0; i < driver->bbs_n; i++) {
        LOG_D("BB 0x%08" PRIx64 " 0x%08" PRIx64, driver->bbs[i].from, driver->bbs[i].to);
    }

    int ret = EXIT_SUCCESS;

    void *context = NULL;
    if (queues_ports_str == NULL) {
        // open interesting and coverage log file
        char filename[PATH_MAX];
        snprintf(filename, PATH_MAX - 1, "%s/%s.interesting.log",
            WORK_PATH, driver->fuzzer_id);
        driver->interesting_log_fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0664);
        if (driver->interesting_log_fd == -1) {
            PLOG_F("failed to open %s", filename);
            free_driver(driver);
            return EXIT_FAILURE;
        }

        snprintf(filename, PATH_MAX - 1, "%s/%s.coverage.log",
            WORK_PATH, driver->fuzzer_id);
        driver->coverage_log_fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0664);
        if (driver->coverage_log_fd == -1) {
            PLOG_F("failed to open %s", filename);
            free_driver(driver);
            return EXIT_FAILURE;
        }
    } else {
        // init zmq connections
        uint32_t port_int_input;
        uint32_t port_use_input;
        uint32_t port_metric;
        ret = sscanf(queues_ports_str, "%" PRIu32 ",%" PRIu32 ",%" PRIu32,
                         &port_int_input, &port_use_input, &port_metric);
        if (ret != 3) {
            LOG_F("failed to parse ports '%s'", queues_ports_str);
            free_driver(driver);
            exit(EXIT_FAILURE);
        }

        context = zmq_ctx_new();
        char buf[PATH_MAX];

        driver->interesting_push = zmq_socket(context, ZMQ_PUSH);
        sprintf(buf, "tcp://localhost:%d", port_int_input);
        if (zmq_connect(driver->interesting_push, buf) == -1) {
            PLOG_F("failed to connect to %s", buf);
            free_driver(driver);
            zmq_ctx_destroy(context);
            exit(EXIT_FAILURE);
        }
        LOG_I("connected to interesting queue on %s", buf);

        driver->use_sub = zmq_socket(context, ZMQ_SUB);
        sprintf(buf, "tcp://localhost:%d", port_use_input);
        if (zmq_connect(driver->use_sub, buf) == -1) {
            PLOG_F("failed to connect to %s", buf);
            free_driver(driver);
            zmq_ctx_destroy(context);
            exit(EXIT_FAILURE);
        }
        if (zmq_setsockopt(driver->use_sub, ZMQ_SUBSCRIBE,
                           SUB_TOPIC, strlen(SUB_TOPIC)) == -1) {
            PLOG_F("failed to set sockopt for use subscription");
            free_driver(driver);
            zmq_ctx_destroy(context);
            exit(EXIT_FAILURE);
        }
        LOG_I("connected to use input queue on %s", buf);

        driver->metric_rep = zmq_socket(context, ZMQ_REP);
        sprintf(buf, "tcp://*:%d", port_metric);
        if (zmq_bind(driver->metric_rep, buf) == -1) {
            PLOG_F("failed to bind to %s", buf);
            free_driver(driver);
            zmq_ctx_destroy(context);
            exit(EXIT_FAILURE);
        }
        LOG_I("bind metric server on %s", buf);
    }

    if (hashset_new(&driver->interesting_seen) == CC_OK) {
        if (hashtable_new(&driver->coverage_info) != CC_OK) {
            LOG_I("failed to create coverage_info");
            ret = EXIT_FAILURE;
        } else {
            signal(SIGINT, sig_handler);
            signal(SIGKILL, sig_handler);
            ret = driver_loop(driver);
        }
    } else {
        LOG_E("failed to create interesting_seen");
        ret = EXIT_FAILURE;
    }

    free_driver(driver);
    if (context != NULL)
        zmq_ctx_destroy(context);

    return ret;
}
