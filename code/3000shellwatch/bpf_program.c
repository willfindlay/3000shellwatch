#include <uapi/asm/unistd_64.h>
#include <linux/sched.h>

/* Type definitions below this line --------------------------------- */

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

/* Map definitions below this line ---------------------------------- */

/* This is a perf event buffer. Perf event buffers allow us
 * to submit events to userspace. Our userspace program will
 * read submitted events at regular intervals. */
BPF_PERF_OUTPUT(syscall_events);

/* This is a percpu_array. It keeps <# cores> many copies of its data
 * and these copies are not synchronized. This means that multiple threads
 * cannot interfere with each other when reading/writing here, making it
 * perfect for storing intermediate values (for example between entry and exit)
 * tracepoints. */
BPF_PERCPU_ARRAY(syscall_intermediate, struct syscall_event, 1);

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
 * we enter a system call. You can see all tracepoints on the system
 * using the "tplist" bcc tool. */
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    /* Load intermediate value from percpu_array */
    struct syscall_event *event = syscall_intermediate.lookup(&zero);
    if (!event)
        return -1;

    /* Store what we know about the system call so far... */
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->tid = (u32)bpf_get_current_pid_tgid();
    event->syscall = (int)args->id;

    return 0;
}

/* This tracepoint is similar to the other one, except it keeps
 * track of every time we return from a system call. */
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    /* Filter PID */
    if (filter())
        return 0;

    int zero = 0;

    /* Load intermediate value from percpu_array */
    struct syscall_event *event = syscall_intermediate.lookup(&zero);
    if (!event)
        return -1;

    /* Now we can fill in the return value! */
    event->ret = args->ret;

    /* This is how we submit an event to userspace. */
    syscall_events.perf_submit(args, event, sizeof(*event));

    return 0;
}
