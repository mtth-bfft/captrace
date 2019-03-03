#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// "<program name>-<pid>" can take up to TASK_COMM_LEN + len(PID_MAX_LIMIT) bytes, way fewer than this
#define MAX_PROGNAME_PID_SIZE 255
#define str(s) #s
#define xstr(s) str(s)
#define max(x,y) ((x) >= (y) ? (x) : (y))
#define CAPABILITY_COUNT ((CAP_LAST_CAP) + 1)

typedef uint64_t cap_num_t;

static const char *KPROBE_DEF = "p:captrace ns_capable_common cap=%%si audit=%%dx\n";
static const char *KPROBE_UNDEF = "-:captrace\n";
static const char *KPROBE_FORMAT = " %" xstr(MAX_PROGNAME_PID_SIZE) "s %*s %*s %Lf : captrace: %*s cap=%" SCNx64 " audit=%" SCNx64 " ";
static volatile int interrupted = 0;
static const char* CAPABILITIES[CAPABILITY_COUNT] = {
    [CAP_CHOWN] = "CAP_CHOWN",
    [CAP_DAC_OVERRIDE] = "CAP_DAC_OVERRIDE",
    [CAP_DAC_READ_SEARCH] = "CAP_DAC_READ_SEARCH",
    [CAP_FOWNER] = "CAP_FOWNER",
    [CAP_FSETID] = "CAP_FSETID",
    [CAP_KILL] = "CAP_KILL",
    [CAP_SETGID] = "CAP_SETGID",
    [CAP_SETUID] = "CAP_SETUID",
    [CAP_SETPCAP] = "CAP_SETPCAP",
    [CAP_LINUX_IMMUTABLE] = "CAP_LINUX_IMMUTABLE",
    [CAP_NET_BIND_SERVICE] = "CAP_NET_BIND_SERVICE",
    [CAP_NET_BROADCAST] = "CAP_NET_BROADCAST",
    [CAP_NET_ADMIN] = "CAP_NET_ADMIN",
    [CAP_NET_RAW] = "CAP_NET_RAW",
    [CAP_IPC_LOCK] = "CAP_IPC_LOCK",
    [CAP_IPC_OWNER] = "CAP_IPC_OWNER",
    [CAP_SYS_MODULE] = "CAP_SYS_MODULE",
    [CAP_SYS_RAWIO] = "CAP_SYS_RAWIO",
    [CAP_SYS_CHROOT] = "CAP_SYS_CHROOT",
    [CAP_SYS_PTRACE] = "CAP_SYS_PTRACE",
    [CAP_SYS_PACCT] = "CAP_SYS_PACCT",
    [CAP_SYS_ADMIN] = "CAP_SYS_ADMIN",
    [CAP_SYS_BOOT] = "CAP_SYS_BOOT",
    [CAP_SYS_NICE] = "CAP_SYS_NICE",
    [CAP_SYS_RESOURCE] = "CAP_SYS_RESOURCE",
    [CAP_SYS_TIME] = "CAP_SYS_TIME",
    [CAP_SYS_TTY_CONFIG] = "CAP_SYS_TTY_CONFIG",
    [CAP_MKNOD] = "CAP_MKNOD",
    [CAP_LEASE] = "CAP_LEASE",
    [CAP_AUDIT_WRITE] = "CAP_AUDIT_WRITE",
    [CAP_AUDIT_CONTROL] = "CAP_AUDIT_CONTROL",
    [CAP_SETFCAP] = "CAP_SETFCAP",
    [CAP_MAC_OVERRIDE] = "CAP_MAC_OVERRIDE",
    [CAP_MAC_ADMIN] = "CAP_MAC_ADMIN",
    [CAP_SYSLOG] = "CAP_SYSLOG",
    [CAP_WAKE_ALARM] = "CAP_WAKE_ALARM",
    [CAP_BLOCK_SUSPEND] = "CAP_BLOCK_SUSPEND",
    [CAP_AUDIT_READ] = "CAP_AUDIT_READ",
};

void print_usage()
{
    fprintf(stderr, "Usage: captrace [-s] [-f] [-p <pid>] [-t <tracefs>] [command [args]]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -s            only show a summary, when exiting\n");
    fprintf(stderr, "  -v            include non-audited capability checks\n");
    fprintf(stderr, "                (by default only audited checks are shown)\n");
    fprintf(stderr, "  -f            also show capabilities in forked children\n");
    fprintf(stderr, "  -p <pid>      only trace the given process id\n");
    fprintf(stderr, "  -t <path>     path to a tracefs mountpoint\n");
    fprintf(stderr, "  [command]     optional command to execute and trace\n");
    exit(-1);
}

/**
 * Resolve the given capability number to a name.
 * Returns NULL for unknown capabilities.
 */
const char* resolve_capability_name(cap_num_t cap_num)
{
    if (cap_num >= CAPABILITY_COUNT)
        return NULL;
    else
        return CAPABILITIES[cap_num];
}

/**
 * Signal handler to break out of the captrace() loop
 */
void signal_handler(int signum)
{
    if (signum != SIGINT && signum != SIGCHLD)
       return;
    interrupted = 1;
}

/**
 * Allocate the given number of bytes, with error handling.
 */
void* safe_alloc(size_t bytes)
{
    void *res = calloc(1, bytes);
    if (res == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
        exit(ENOMEM);
    }
    return res;
}

/**
 * Resize the given buffer to hold the given size, with
 * error handling.
 */
void* safe_realloc(void *old, size_t bytes)
{
    void *res = NULL;
    if (old == NULL)
        return safe_alloc(bytes);
    res = realloc(old, bytes);
    if (res == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
        exit(ENOMEM);
    }
    return res;
}

/**
 * Fills the given buffer with the given process'
 * executable absolute path. Returns 0 on success,
 * an error code otherwise.
 */
int get_prog_path_by_pid(uint64_t pid, char *buf, size_t buf_len)
{
    char procpath[255] = { 0 };
    snprintf(procpath, sizeof(procpath), "/proc/%" PRIu64 "/exe", pid);
    ssize_t res_len = readlink(procpath, buf, buf_len);
    if (res_len == (ssize_t)buf_len)
        return ENAMETOOLONG;
    else if (res_len < 0)
        return errno;
    buf[res_len] = '\0';
    return 0;
}

/**
 * Given a relative path within a tracefs, write the given
 * formatted string into that file. Returns 0 on success,
 * an error code otherwise.
 */
int write_tracing(int tracefs_fd, const char *path, const char *format, ...)
{
    int res = 0;
    int tmp_fd = -1;
    char buffer[256] = { 0 };
    va_list args;
    ssize_t bytes_written = 0;

    va_start(args, format);
    tmp_fd = openat(tracefs_fd, path, O_WRONLY | O_TRUNC);
    if (tmp_fd < 0)
    {
        res = errno;
        fprintf(stderr, "Error: openat(%s) code %d\n", path, res);
        goto cleanup;
    }

    vsnprintf(buffer, sizeof(buffer), format, args);
    bytes_written = write(tmp_fd, buffer, strlen(buffer));
    res = (bytes_written < 0 ? errno : 0);

cleanup:
    va_end(args);
    if (tmp_fd > 0)
        close(tmp_fd);
    return res;
}

/**
 * Sets up a tracing session. Optionally restricts the session to a given PID
 * instead of the whole system. Optionally traces the child processes of the target.
 * When summarize is 0, capabilities are printed as they are used, otherwise,
 * a summary of all capabilities used is printed at the end. Returns 0 on success,
 * an error code otherwise.
 */
int setup_tracing(int tracefs_fd, uint64_t target_pid, int follow_forks)
{
    int res = 0;

    res = write_tracing(tracefs_fd, "kprobe_events", KPROBE_DEF);
    if (res != 0 && res != EBUSY) // ignore error in case of leftover probe from previous session
    {
        fprintf(stderr, "Error: unable to create kprobe, code %d\n", res);
        goto cleanup;
    } 

    if (follow_forks > 0)
    {
        res = write_tracing(tracefs_fd, "trace_options", "event-fork\n");
        if (res != 0)
        {
            fprintf(stderr, "Error: unable to set trace option event-fork, code %d\n", res);
        }
    }

    if (target_pid > 0)
    {
        res = write_tracing(tracefs_fd, "set_event_pid", "%u\n", target_pid);
        if (res != 0)
        {
            fprintf(stderr, "Error: unable to set kprobe pid target, code %d\n", res);
            goto cleanup;
        }
    }
    else
    {
        res = write_tracing(tracefs_fd, "set_event_pid", "\n");
        if (res != 0)
        {
            fprintf(stderr, "Error: unable to remove kprobe target pids, code %d\n", res);
            goto cleanup;
        }
    }

    res = write_tracing(tracefs_fd, "events/kprobes/captrace/enable", "1\n");
    if (res != 0)
    {
        fprintf(stderr, "Error: unable to enable kprobe, code %d\n", res);
        goto cleanup;
    }

    res = write_tracing(tracefs_fd, "tracing_on", "1\n");
    if (res != 0)
    {
        fprintf(stderr, "Error: unable to enable tracing, code %d\n", res);
        goto cleanup;
    }

cleanup:
    return res;
}

/**
 * Runs in a loop (until interrupted by setting interrupted=1)
 * printing capabilities as they are used if summarize=0.
 * If summarize=1, only statistics are printed, at the end.
 * Returns 0 on success, an error code otherwise.
 */
int process_tracing(int tracefs_fd, int audited_only, int summarize, FILE *out)
{
    int res = 0;
    int pipe_fd = -1;
    uint64_t this_pid = getpid();
    FILE *pipe_file = NULL;
    char *cap_prog = safe_alloc(MAX_PROGNAME_PID_SIZE + 1);
    char *cap_prog_path = safe_alloc(PATH_MAX + 1);
    uint64_t cap_pid = 0;
    long double cap_time = 0.0;
    cap_num_t cap_num = 0;
    uint64_t cap_audit = 0;
    const char *cap_str = NULL;
    uint64_t *counters = safe_alloc(CAPABILITY_COUNT * sizeof(uint64_t));
    size_t max_cap_len = 0;
    struct sigaction sigact = { 0 };

    for (size_t i = 0; i < CAPABILITY_COUNT; i++)
    {
        if (CAPABILITIES[i] != NULL)
            max_cap_len = max(strlen(CAPABILITIES[i]), max_cap_len);
    }

    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    res = sigaction(SIGINT, &sigact, NULL);
    if (res != 0)
        fprintf(stderr, "Error: unable to setup signal handlers\n");
    res = sigaction(SIGCHLD, &sigact, NULL);
    if (res != 0)
        fprintf(stderr, "Error: unable to setup signal handlers\n");
    interrupted = 0;

    pipe_fd = openat(tracefs_fd, "trace_pipe", O_RDONLY);
    if (pipe_fd < 0)
    {
        res = errno;
        fprintf(stderr, "Error: openat(trace_pipe) code %d\n", res);
        goto cleanup;
    }
    pipe_file = fdopen(pipe_fd, "r");
    if (pipe_file == NULL)
    {
        res = errno;
        fprintf(stderr, "Error: fdopen(trace_pipe) code %d\n", res);
        goto cleanup;
    }

    while ((res = fscanf(pipe_file, KPROBE_FORMAT,
        cap_prog, &cap_time, &cap_num, &cap_audit)) != EOF)
    {
        if (interrupted)
            break;
        if (res != 4)
            continue;
        cap_pid = 0;
        // Parse PID from <prog name>-<pid> (prog name may include dashes...)
        for (int i = strlen(cap_prog); i >= 0; i--)
        {
            if (cap_prog[i] == '-')
            {
                cap_pid = atoll(cap_prog + i + 1);
                cap_prog[i] = '\0';
                break;
            }
        }
        if (cap_audit == 0 && audited_only)
            continue;
        if (cap_pid == 0)
        {
            fprintf(stderr, "Error: cannot parse PID from '%s'\n", cap_prog);
            continue;
        }
        if (cap_pid == this_pid)
            continue;
        if (cap_num < CAPABILITY_COUNT)
            counters[cap_num]++;
        if (summarize)
            continue;
        res = get_prog_path_by_pid(cap_pid, cap_prog_path, PATH_MAX + 1);
        if (res != 0)
            snprintf(cap_prog_path, PATH_MAX + 1, cap_prog);
        cap_str = resolve_capability_name(cap_num);
        if (cap_str == NULL)
            fprintf(out, "%Lf\t%" PRIu64 "\t%s\t%-*" PRIu64 "\n",
                cap_time, cap_pid, cap_prog_path, (int)max_cap_len, cap_num);
        else
            fprintf(out, "%Lf\t%" PRIu64 "\t%s\t%-*s\n",
                cap_time, cap_pid, cap_prog_path, (int)max_cap_len, cap_str);
    }
    if (!interrupted && res != 4)
        fprintf(stderr, "Error while reading trace event: code %u error %u\n", res, errno);
    if (interrupted)
        fprintf(out, "\n");
    if (summarize)
    {
        fprintf(out, "%-*s uses\n", (int)max_cap_len, "capability");
        fprintf(out, "%-*s ----\n", (int)max_cap_len, "----------");
        for (size_t i = 0; i < CAPABILITY_COUNT; i++)
        {
            if (counters[i] == 0)
                continue;
            fprintf(out, "%-*s %" PRIu64 "\n", (int)max_cap_len, CAPABILITIES[i], counters[i]);
        }
    }

cleanup:
    if (pipe_fd > 0)
        close(pipe_fd);
    if (cap_prog != NULL)
        free(cap_prog);
    if (cap_prog_path != NULL)
        free(cap_prog_path);
    return res;
}

/**
 * Called at the end of a tracing session, to remove our kprobe
 * (and its overhead) and to reset tracing settings to their defaults.
 * Returns 0 on success, an error code otherwise.
 */
int cleanup_tracing(int tracefs_fd)
{
    int res = 0;

    res = write_tracing(tracefs_fd, "events/kprobes/captrace/enable", "0\n");
    if (res != 0)
        fprintf(stderr, "Error: unable to disable kprobe, code %d\n", res);
    res = write_tracing(tracefs_fd, "kprobe_events", KPROBE_UNDEF);
    if (res != 0 && res != ENOENT)
        fprintf(stderr, "Error: unable to undefine kprobe, code %d\n", res);
    res = write_tracing(tracefs_fd, "trace_options", "noevent-fork\n");
    if (res != 0)
        fprintf(stderr, "Error: unable to undefine kprobe, code %d\n", res);
    res = write_tracing(tracefs_fd, "set_event_pid", "\n");
    if (res != 0)
        fprintf(stderr, "Error: unable to remove trace PID filter, code %d\n", res);
    res = write_tracing(tracefs_fd, "tracing_on", "0\n");
    if (res != 0)
        fprintf(stderr, "Error: unable to disable tracing, code %d\n", res);
    return res;
}

/**
 * Parses command line arguments, sets up the child
 * process if a command to execute was given instead of
 * a PID, starts tracing and cleans up.
 */
int main(int argc, char* argv[])
{
    int res = 0;
    int follow_forks = 0;
    int summarize = 0;
    int audited_only = 1;
    uint64_t target_pid = 0;
    const char *tracefs_path = "/sys/kernel/debug/tracing";
    int tracefs_fd = -1;
    int target_is_child = 0;
    int syncpipe_fd[2] = { 0 };

    while ((res = getopt(argc, argv, "+sfvt:p:")) != -1)
    {
        switch (res)
        {
        case 's':
            summarize = 1;
            break;
        case 'f':
            follow_forks = 1;
            break;
        case 'p':
            target_pid = atoi(optarg);
            if (target_pid == 0)
            {
                fprintf(stderr, "Error: invalid PID\n");
                print_usage();
            }
            break;
        case 't':
            tracefs_path = optarg;
            break;
        case 'v':
            audited_only = 0;
            break;
        default:
            print_usage();
        }
    }

    // Leftover arguments are a command to execute
    if (optind < argc)
    {
        target_is_child = 1;
        if (target_pid != 0)
        {
            fprintf(stderr, "Error: only one target can be specified at a time\n");
            print_usage();
        }
        res = pipe2(syncpipe_fd, O_CLOEXEC);
        if (res != 0)
        {
            fprintf(stderr, "Error: pipe(): %d\n", errno);
            exit(errno);
        }
        target_pid = fork();
        if (target_pid == 0)
        {
            // In child. Wait for parent to signal it is ready to trace
            close(syncpipe_fd[1]);
            if (read(syncpipe_fd[0], &res, sizeof(res)) != sizeof(res))
            {
                fprintf(stderr, "Error waiting for parent process: %d\n", errno);
                exit(errno);
            }
            execvp(argv[optind], &(argv[optind]));
            fprintf(stderr, "Error: execve(%s): %d\n", argv[optind], errno);
            exit(errno);
        }
        close(syncpipe_fd[0]);
    }

    tracefs_fd = open(tracefs_path, O_PATH | O_DIRECTORY);
    if (tracefs_fd < 0)
    {
        res = errno;
        if (res == EACCES)
            fprintf(stderr, "Error: cannot access tracefs, run me with higher privileges?\n");
        else
            fprintf(stderr, "Error: opening a tracefs (code %d), please specify the path to a tracefs with -t\n", res);
        goto cleanup;
    }

    res = setup_tracing(tracefs_fd, target_pid, follow_forks);
    if (res != 0)
        goto cleanup;

    if (target_is_child)
    {
        if (write(syncpipe_fd[1], &res, sizeof(res)) != sizeof(res))
        {
            fprintf(stderr, "Error signaling child process: %d\n", errno);
            exit(errno);
        }
        close(syncpipe_fd[1]);
    }

    res = process_tracing(tracefs_fd, audited_only, summarize, (target_is_child ? stderr : stdout));

cleanup:
    if (tracefs_fd >= 0)
    {
        cleanup_tracing(tracefs_fd);
        close(tracefs_fd);
    }
    return res;
}
