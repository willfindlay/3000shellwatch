#! /usr/bin/env python3

import os, sys
import time
import argparse

from utils import syscall_name, syscall_ret

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

if __name__ == '__main__':
    print(f'Tracing pid {args.pid}, ctrl-c to exit...', file=sys.stderr)
    try:
        while 1:
            bpf.perf_buffer_poll(30)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        print('Goodbye BPF world!', file=sys.stderr)
