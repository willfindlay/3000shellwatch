#include <uapi/asm/unistd_64.h>
#include <linux/sched.h>
#include <linux/signal_types.h>

/* Type definitions below this line --------------------------------- */

#define MAX_STRLEN 512

/* This struct will contain useful information about system calls.
 * We will use to to pass data between system call tracepoints and
 * to return useful information back to userspace. */
struct syscall_event
{
    int syscall;
    long ret;
};

struct fgets_event
{
    void *bufptr;
    char str[MAX_STRLEN];
};

struct signal_deliver_event
{
    void *ksigptr;
    int sending_pid;
    int signal;
};

/* Map definitions below this line ---------------------------------- */

/* This is a perf event buffer. Perf event buffers allow us
 * to submit events to userspace. Our userspace program will
 * read submitted events at regular intervals. */
BPF_PERF_OUTPUT(syscall_events);
BPF_PERF_OUTPUT(fgets_events);
BPF_PERF_OUTPUT(signal_deliver_events);

/* This is used to store intermediate values
 * between entry and exit points. For example, storing the argument
 * to fgets and printing it on return. */
BPF_ARRAY(fgets_intermediate, struct fgets_event, 1);
BPF_ARRAY(signal_deliver_intermediate, struct signal_deliver_event, 1);

/* This is used to keep track of value distributions.
 * We can use the data to draw fancy histograms in userspace. */
BPF_HISTOGRAM(readlens, long, 10240);

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
    event.syscall = (int)args->id;

    /* If we are in a read(2) call, let's keep track of a histogram of lengths */
    if (args->id == __NR_read && args->ret >= 0)
        readlens.increment(args->ret);

    /* This is how we submit an event to userspace. */
    syscall_events.perf_submit(args, &event, sizeof(event));

    return 0;
}

/* Part 1 of the get_signal kprobe */
int kprobe__get_signal(struct pt_regs *ctx, struct ksignal *ksig)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    struct signal_deliver_event *event = signal_deliver_intermediate.lookup(&zero);
    if (!event)
        return -1;

    event->ksigptr = ksig;

    return 0;
}

/* Part 2 of the get_signal kprobe */
int kretprobe__get_signal(struct pt_regs *ctx)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    struct signal_deliver_event *event = signal_deliver_intermediate.lookup(&zero);
    if (!event)
        return -1;

    struct ksignal *ksig = (struct ksignal *)event->ksigptr;
    if (!ksig)
        return -2;

    event->signal = ksig->info.si_signo;
    event->sending_pid = ksig->info.si_pid;

    signal_deliver_events.perf_submit(ctx, event, sizeof(*event));

    return 0;
}

/* Part 1 of the fgets uprobe */
int uprobe_fgets(struct pt_regs *ctx)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    struct fgets_event *event = fgets_intermediate.lookup(&zero);
    if (!event)
        return -1;

    /* Store location of parameter 1 (the buffer) */
    event->bufptr = (void *)PT_REGS_PARM1(ctx);

    return 0;
}

/* Part 2 of the fgets uprobe */
int uretprobe_fgets(struct pt_regs *ctx)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    struct fgets_event *event = fgets_intermediate.lookup(&zero);
    if (!event)
        return -1;

    /* Read the buffer into event.str */
    bpf_probe_read_str(event->str, sizeof(event->str), event->bufptr);

    fgets_events.perf_submit(ctx, event, sizeof(*event));

    return 0;
}
