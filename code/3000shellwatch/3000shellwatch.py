#! /usr/bin/env python3

import os, sys
import time
import argparse

from utils import syscall_name, syscall_ret, signal_name

from bcc import BPF

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--pid', type=int, required=1,
        help='PID of 3000shell.')
args = parser.parse_args()

# Set BPF program flags
flags = []
flags.append(f'-I{os.path.realpath(os.path.dirname(__file__))}')
flags.append(f'-DFILTER_PID={args.pid}')

# Load BPF program
bpf = BPF(src_file='bpf_program.c', cflags=flags)

# Define a hook for syscall_events perf buffer
def syscall_events(cpu, data, size):
    event = bpf['syscall_events'].event(data)
    print(f'syscall {syscall_name(event.syscall):<16s} = {syscall_ret(event.ret):>8s}')
bpf['syscall_events'].open_perf_buffer(syscall_events)

# Define a hook for signal_events perf buffer
def signal_deliver_events(cpu, data, size):
    event = bpf['signal_deliver_events'].event(data)
    print(f'3000shell received {signal_name(event.signal)} from pid {event.sending_pid}')
bpf['signal_deliver_events'].open_perf_buffer(signal_deliver_events)

# Define a hook for fgets_events perf buffer
def fgets_events(cpu, data, size):
    event = bpf['fgets_events'].event(data)
    print(f'user wrote: \"{event.str.decode("utf-8").strip()}\"')
bpf['fgets_events'].open_perf_buffer(fgets_events)

# Attach uprobes
bpf.attach_uprobe(name='c', sym='fgets', fn_name='uprobe_fgets')
bpf.attach_uretprobe(name='c', sym='fgets', fn_name='uretprobe_fgets')

if __name__ == '__main__':
    print(f'Tracing pid {args.pid}, ctrl-c to exit...', file=sys.stderr)
    try:
        while 1:
            bpf.perf_buffer_poll(30)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print()
        print('Here is the distribution of read lengths:')
        bpf['readlens'].print_linear_hist('read lengths:')
        print(file=sys.stderr)
        print('Goodbye BPF world!', file=sys.stderr)
