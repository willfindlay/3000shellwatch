#include <uapi/asm/unistd_64.h>
#include <linux/sched.h>

/* Type definitions below this line --------------------------------- */

#define MAX_STRLEN 32

/* This struct will contain useful information about system calls.
 * We will use to to pass data between system call tracepoints and
 * to return useful information back to userspace. */
struct syscall_event
{
    u32 pid;
    u32 tid;
    int syscall;
    long ret;
};

struct fgets_event
{
    u32 pid;
    u32 tid;
    void *bufptr;
    char str[MAX_STRLEN];
};

/* Map definitions below this line ---------------------------------- */

/* This is a perf event buffer. Perf event buffers allow us
 * to submit events to userspace. Our userspace program will
 * read submitted events at regular intervals. */
BPF_PERF_OUTPUT(syscall_events);
BPF_PERF_OUTPUT(fgets_events);

/* This is used to store intermediate values
 * between entry and exit points. For example, storing the argument
 * to fgets and printing it on return. */
BPF_ARRAY(fgets_intermediate, struct fgets_event, 1);

/* Helper functions below this line --------------------------------- */

/* This is a simple filter() function that allows
 * us to look at the specified process, ignoring others. */
/* Return 0 on pass, 1 on fail */
static int filter()
{
    u32 pid = (bpf_get_current_pid_tgid() >> 32);
    if (pid == FILTER_PID)
        return 0;
    return 1;
}

/* BPF programs below this line ------------------------------------- */

/* This is a tracepoint. They represent a stable API for accessing
 * various events within the kernel. This one keeps track of every time
 * we return from a system call. You can see all tracepoints on the system
 * using the "tplist" bcc tool. */
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    if (args->id < 0)
        return 0;

    /* Load intermediate value from percpu_array */
    struct syscall_event event = {};

    /* Store what we know about the system call */
    event.ret = args->ret;
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event.tid = (u32)bpf_get_current_pid_tgid();
    event.syscall = (int)args->id;

    /* This is how we submit an event to userspace. */
    syscall_events.perf_submit(args, &event, sizeof(event));

    return 0;
}

int uprobe_fgets(struct pt_regs *ctx)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    struct fgets_event *event = fgets_intermediate.lookup(&zero);
    if (!event)
        return -1;

    /* Read information into intermediate event */
    event->bufptr = (void *)PT_REGS_PARM1(ctx);
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->tid = (u32)bpf_get_current_pid_tgid();

    return 0;
}

int uretprobe_fgets(struct pt_regs *ctx)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    struct fgets_event *event = fgets_intermediate.lookup(&zero);
    if (!event)
        return -1;

    /* Read buffer into event.str */
    bpf_probe_read_str(event->str, sizeof(event->str), event->bufptr);

    fgets_events.perf_submit(ctx, event, sizeof(*event));

    return 0;
}
