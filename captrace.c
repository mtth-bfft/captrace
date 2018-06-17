#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Comm+pid can take up to TASK_COMM_LEN + len(PID_MAX_LIMIT) bytes, way fewer than this
#define MAX_PROG_SIZE 255
#define str(s) #s
#define xstr(s) str(s)
#define max(x,y) ((x) >= (y) ? (x) : (y))

static const char *KPROBE_DEF = "p:captrace ns_capable_common cap=%%si audit=%%dx\n";
static const char *KPROBE_UNDEF = "-:captrace\n";
static const char *KPROBE_FORMAT = " %" xstr(MAX_PROG_SIZE) "s %*s .... %*Lf : captrace: %*s cap=%" SCNx64 " audit=%" SCNx64 " ";
static const char *tracefs_path = "/sys/kernel/debug/tracing";
static int tracefs_fd = -1;
static volatile int interrupted = 0;
static const char* CAPABILITIES[] = {
    [0]  = "CAP_CHOWN",
    [1]  = "CAP_DAC_OVERRIDE",
    [2]  = "CAP_DAC_READ_SEARCH",
    [3]  = "CAP_FOWNER",
    [4]  = "CAP_FSETID",
    [5]  = "CAP_KILL",
    [6]  = "CAP_SETGID",
    [7]  = "CAP_SETUID",
    [8]  = "CAP_SETPCAP",
    [9]  = "CAP_LINUX_IMMUTABLE",
    [10] = "CAP_NET_BIND_SERVICE",
    [11] = "CAP_NET_BROADCAST",
    [12] = "CAP_NET_ADMIN",
    [13] = "CAP_NET_RAW",
    [14] = "CAP_IPC_LOCK",
    [15] = "CAP_IPC_OWNER",
    [16] = "CAP_SYS_MODULE",
    [17] = "CAP_SYS_RAWIO",
    [18] = "CAP_SYS_CHROOT",
    [19] = "CAP_SYS_PTRACE",
    [20] = "CAP_SYS_PACCT",
    [21] = "CAP_SYS_ADMIN",
    [22] = "CAP_SYS_BOOT",
    [23] = "CAP_SYS_NICE",
    [24] = "CAP_SYS_RESOURCE",
    [25] = "CAP_SYS_TIME",
    [26] = "CAP_SYS_TTY_CONFIG",
    [27] = "CAP_MKNOD",
    [28] = "CAP_LEASE",
    [29] = "CAP_AUDIT_WRITE",
    [30] = "CAP_AUDIT_CONTROL",
    [31] = "CAP_SETFCAP",
    [32] = "CAP_MAC_OVERRIDE",
    [33] = "CAP_MAC_ADMIN",
    [34] = "CAP_SYSLOG",
    [35] = "CAP_WAKE_ALARM",
    [36] = "CAP_BLOCK_SUSPEND",
    [37] = "AUDIT_READ",
};
static const size_t CAPABILITIES_COUNT = sizeof(CAPABILITIES)/sizeof(CAPABILITIES[0]);

void print_usage()
{
    fprintf(stderr, "Usage: captrace [-v] [-f] [-p <pid>] [-t <tracefs>]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -f            also captrace forked children\n");
    fprintf(stderr, "  -p <pid>      only trace that process id\n");
    fprintf(stderr, "  -t <path>     path to a tracefs mountpoint\n");
    fprintf(stderr, "  -v            show non-audited capability checks\n");
    exit(-1);
}

void sigint_handler(int signum)
{
    if (signum != SIGINT)
       return;
    interrupted = 1;
}

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

void* safe_realloc(void *old, size_t bytes)
{
    void *res = realloc(old, bytes);
    if (res == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
	exit(ENOMEM);
    }
    return res;
}

int get_prog_path(uint64_t pid, char *buf, size_t buf_len)
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

int write_tracing(const char *path, const char *format, ...)
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

int main(int argc, char* argv[])
{
    int res = 0;
    int follow_forks = 0;
    int summarize = 0;
    int verbose = 0;
    uint64_t target = 0;
    uint64_t this_pid = getpid();
    size_t max_cap_len = 0;
    int pipe_fd = -1;
    FILE *pipe_file = NULL;
    char *cap_prog = safe_alloc(MAX_PROG_SIZE + 1);
    char *cap_prog_path = safe_alloc(PATH_MAX + 1);
    uint64_t cap_pid = 0;
    //long double cap_time = 0.0;
    uint64_t cap_num = 0;
    uint64_t cap_audit = 0;
    const char *cap_str = NULL;
    uint64_t *counters = safe_alloc((CAPABILITIES_COUNT + 1)*sizeof(uint64_t));

    while ((res = getopt(argc, argv, "+cfvp:")) != -1)
    {
	switch (res)
	{
        case 'c':
            summarize = 1;
	    break;
        case 'f':
            follow_forks = 1;
	    break;
	case 'p':
	    target = atoi(optarg);
	    if (target == 0)
	    {
                fprintf(stderr, "Error: invalid PID\n");
		print_usage();
	    }
	    break;
        case 't':
	    tracefs_path = optarg;
	    break;
	case 'v':
	    verbose = 1;
	    break;
	default:
	    print_usage();
	}
    }

    for (size_t i = 0; i < CAPABILITIES_COUNT; i++)
    {
        max_cap_len = max(strlen(CAPABILITIES[i]), max_cap_len);
    }

    tracefs_fd = open(tracefs_path, O_PATH | O_DIRECTORY);
    if (tracefs_fd < 0)
    {
	res = errno;
	if (res == EACCES)
            fprintf(stderr, "Error: cannot access tracefs, run me with higher privileges?\n");
	else
            fprintf(stderr, "Error: open(%s) code %d, try specifying -t ?\n", tracefs_path, res);
	goto cleanup;
    }

    res = write_tracing("kprobe_events", KPROBE_DEF);
    if (res != 0)
    {
        fprintf(stderr, "Error: unable to create kprobe, code %d\n", res);
	goto cleanup;
    } 

    if (follow_forks > 0)
    {
	res = write_tracing("trace_options", "event-fork\n");
	if (res != 0)
	{
	    fprintf(stderr, "Error: unable to set trace option event-fork, code %d\n", res);
	}
    }

    if (target > 0)
    {
	res = write_tracing("set_event_pid", "%u\n", target);
	if (res != 0)
	{
	    fprintf(stderr, "Error: unable to set kprobe pid target, code %d\n", res);
	    goto cleanup;
	}
    }
    else
    {
	res = write_tracing("set_event_pid", "\n");
	if (res != 0)
	{
	    fprintf(stderr, "Error: unable to remove kprobe target pids, code %d\n", res);
	    goto cleanup;
	}
    }

    res = write_tracing("events/kprobes/captrace/enable", "1\n");
    if (res != 0)
    {
        fprintf(stderr, "Error: unable to enable kprobe, code %d\n", res);
	goto cleanup;
    }
    
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
    res = write_tracing("tracing_on", "1\n");
    if (res != 0)
    {
        fprintf(stderr, "Error: unable to enable tracing, code %d\n", res);
        goto cleanup;
    } 

    signal(SIGINT, sigint_handler);

    while ((res = fscanf(pipe_file, KPROBE_FORMAT,
        cap_prog, &cap_num, &cap_audit)) != EOF)
    {
	if (interrupted || res != 3)
            break;
	if (!cap_audit && !verbose)
            continue;
	cap_pid = 0;
	for (int i = strlen(cap_prog); i >= 0; i--)
        {
            if (cap_prog[i] == '-')
	    {
                cap_pid = atoll(cap_prog + i + 1);
		cap_prog[i] = '\0';
		break;
	    }
	}
        if (cap_pid == 0)
        {
	    fprintf(stderr, "Error: cannot read PID from '%s'\n", cap_prog);
	    continue;
	}
	if (cap_pid == this_pid)
            continue;
	if (cap_num >= CAPABILITIES_COUNT)
        {
	    fprintf(stderr, "Error: unknown capability %" PRIu64 "\n", cap_num);
	    continue;
	}
	counters[cap_num]++;
	if (summarize)
	    continue;
        cap_str = CAPABILITIES[cap_num];
	res = get_prog_path(cap_pid, cap_prog_path, PATH_MAX + 1);
	if (res != 0)
            snprintf(cap_prog_path, PATH_MAX + 1, cap_prog);
	printf("%-*s\t%" PRIu64 "\t%s\n", (int)max_cap_len, cap_str, cap_pid, cap_prog_path);
    }
    if (!interrupted && res != 4)
    {
        fprintf(stderr, "Error while reading trace event: code %u error %u\n", res, errno);
    }
    if (interrupted)
	fprintf(stderr, "\n");
    if (summarize)
    {
	fprintf(stderr, "%-*s uses\n", (int)max_cap_len, "capability");
	fprintf(stderr, "%-*s ----\n", (int)max_cap_len, "----------");
	for (size_t i = 0; i < CAPABILITIES_COUNT; i++)
	{
            if (counters[i] == 0)
		continue;
	    printf("%-*s %" PRIu64 "\n", (int)max_cap_len, CAPABILITIES[i], counters[i]);
	}
    }

cleanup:
    if (pipe_fd > 0)
        close(pipe_fd);
    if (cap_prog != NULL)
        free(cap_prog);
    if (cap_prog_path != NULL)
	free(cap_prog_path);
    write_tracing("events/kprobes/captrace/enable", "0\n");
    write_tracing("kprobe_events", KPROBE_UNDEF);
    write_tracing("trace_options", "noevent-fork\n");
    write_tracing("tracing_on", "0\n");
    return res;
}
