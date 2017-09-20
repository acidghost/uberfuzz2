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


typedef struct driver {
    const char *fuzzer_id;
    char **fuzzer;
    size_t fuzzer_n;
    const char **sut;
    const char *fuzzer_corpus_path;
    section_bounds_t *sec_bounds;
    basic_block_t *bbs;
    size_t bbs_n;
    size_t input_n;
    void *interesting_push;
    void *use_sub;
    void *metric_rep;
    const char *data_path;
} driver_t;


typedef struct branch {
    uint64_t from;
    uint64_t to;
} branch_t;


#define BUF_SZ              (1024 * 1024)


bool keep_running = true;


static bool process_interesting_input(driver_t *driver, uint8_t *buf, size_t size)
{
    bts_branch_t *bts_start;
    uint64_t count;
    int perf_ret = perf_monitor_api(buf, size, driver->sut, &bts_start, &count);
    if (perf_ret == PERF_FAILURE) {
        LOG_F("failed perf monitoring");
        return false;
    }

    const section_bounds_t *sec_bounds = driver->sec_bounds;
    const uint64_t sec_start = sec_bounds ? sec_bounds->sec_start : 0;
    const uint64_t sec_end = sec_bounds ? sec_bounds->sec_end : 0;

    branch_t branches[count];
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

    char coverage_filename[PATH_MAX];
    snprintf(coverage_filename, PATH_MAX - 1, "%s/%05zu.coverage",
             driver->data_path, driver->input_n);

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
    fclose(coverage_file);

    char input_filename[PATH_MAX];
    snprintf(input_filename, PATH_MAX - 1, "%s/%05zu.input",
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
    fclose(coverage_file);

    char message[PATH_MAX * 2];
    snprintf(message, (PATH_MAX * 2) - 1, "%s %s %s",
             driver->fuzzer_id, input_filename, coverage_filename);
    if (zmq_send(driver->interesting_push, message, strlen(message), 0) == -1) {
        PLOG_F("failed pushing on the interesting queue");
        return false;
    }

    return true;
}


static pid_t start_fuzzer(driver_t *driver)
{
    pid_t pid = fork();
    if (pid < 0) {
        PLOG_F("failed to fork");
        return -1;
    } else if (pid == 0) {
        // child, run fuzzer
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd == -1) {
            PLOG_F("failed to open /dev/null");
            abort();
        }
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        execv(driver->fuzzer[0], driver->fuzzer);
        PLOG_F("failed to execv fuzzer");
        abort();
    } else {
        // parent, child_pid = pid
        return pid;
    }
}


static int driver_loop(driver_t *driver)
{
    int ret = EXIT_SUCCESS;
    pid_t fuzzer_pid = start_fuzzer(driver);
    if (fuzzer_pid == -1) {
        LOG_F("failed to start fuzzer %s", driver->fuzzer[0]);
        return EXIT_FAILURE;
    } else {
        LOG_I("fuzzer %s started (pid=%d)", driver->fuzzer[0], fuzzer_pid);
    }

    int watch_d = 0;
    int inotify_fd = inotify_setup(driver->fuzzer_corpus_path, &keep_running, &watch_d);
    if (inotify_fd == -1) {
        LOG_F("failed to setup inotify on %s", driver->fuzzer_corpus_path);
        return EXIT_FAILURE;
    }

    while (keep_running) {
        if (kill(fuzzer_pid, 0) == -1 && errno == ESRCH) {
            LOG_I("fuzzer stopped, exiting");
            break;
        }

        if (!keep_running) {
            if (kill(fuzzer_pid, SIGKILL) == -1) {
                PLOG_F("failed to kill fuzzer (pid=%d)", fuzzer_pid);
                ret = EXIT_FAILURE;
            }
            break;
        }

        // 1. look if fuzzer has a new input -> push to queue
        uint8_t buf[BUF_SZ];
        int size = inotify_maybe_read(inotify_fd, watch_d, driver->fuzzer_corpus_path,
                                      buf, BUF_SZ);
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

        // 2. look for metric requests -> reply to request
        // 3. look for new inputs to use/fuzz -> inject into fuzzer

        usleep(100);
    }

    close(inotify_fd);
    return ret;
}


void int_sig_handler(int signum)
{
    keep_running = false;
}


static bool parse_fuzzer_cmd(driver_t *driver, const char *fuzzer_cmd_filename)
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
        size_t len = strlen(buf);
        driver->fuzzer[i] = malloc(sizeof(char) * len);
        assert(driver->fuzzer[i] != NULL);
        strncpy(driver->fuzzer[i], buf, len - 1);       // skip newline
        i++;
    }

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


static void free_driver(driver_t *driver)
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

    free(driver);
}


static void usage(const char *progname)
{
    printf("usage: %s -i fuzzer_id -f fuzzer_cmd [-s .section] -b r2bb.sh "
           "-c corpus -p p1,p2,p3 -d data_path -- command [args]\n", progname);
}


int main(int argc, char const *argv[]) {
    log_level = INFO;
    char *sec_name = NULL;
    char *basic_block_script = NULL;
    char *queues_ports_str = NULL;

    driver_t *driver = malloc(sizeof(driver_t));
    assert(driver != NULL);
    memset(driver, 0, sizeof(driver_t));

    int opt;
    while ((opt = getopt(argc, (char * const*) argv, "i:f:s:b:c:p:d:")) != -1) {
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
        }
    }

    if (argc == optind || driver->fuzzer_id == NULL ||
        basic_block_script == NULL || driver->fuzzer_corpus_path == NULL ||
        queues_ports_str == NULL || driver->data_path == NULL) {
        free_driver(driver);
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    driver->sut = argv + optind;

    LOG_I("driver on %s", driver->fuzzer[0]);

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

        LOG_I("SUT %s (%s 0x%" PRIx64 " 0x%" PRIx64 " %" PRIi64 ")",
            driver->sut[0], sec_name, driver->sec_bounds->sec_start,
            driver->sec_bounds->sec_end, sec_size);
    } else {
        LOG_I("SUT %s (all code)", driver->sut[0]);
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

    uint32_t port_int_input;
    uint32_t port_use_input;
    uint32_t port_metric;
    int ret = sscanf(queues_ports_str, "%" PRIu32 ",%" PRIu32 ",%" PRIu32,
                     &port_int_input, &port_use_input, &port_metric);
    if (ret != 3) {
        LOG_F("failed to parse ports '%s'", queues_ports_str);
        free_driver(driver);
        exit(EXIT_FAILURE);
    }

    void *context = zmq_ctx_new();
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
    if (zmq_setsockopt(driver->use_sub, ZMQ_SUBSCRIBE, "A", 1) == -1) {
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

    signal(SIGINT, int_sig_handler);
    ret = driver_loop(driver);

    free_driver(driver);
    zmq_ctx_destroy(context);
    return ret;
}
