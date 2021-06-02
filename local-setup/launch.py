#!/usr/bin/env python3
"""
Launch a local dev setup consisting of one substraTEE-node and two workers.
"""
import atexit
import signal
import sys
from subprocess import Popen, STDOUT

from py.worker import Worker

log_dir = '../log'
node_log = open(f'{log_dir}/node.log', 'w')

source_bin_folder = '../bin'
node_bin = '../../substraTEE-node/target/release/substratee-node'
w1_working_dir = '/tmp/w1'
w2_working_dir = '/tmp/w2'

processes = []


def cleanup():
    print("cleaning up processes")
    for p in processes:
        try:
            p.kill()
        except:
            pass


atexit.register(cleanup)


def signal_handler(sig, frame):
    sys.exit()


signal.signal(signal.SIGINT, signal_handler)

print('Starting substraTee-node-process in background')
node = processes.append(
    Popen([node_bin, '--tmp', '--dev', '-lruntime=debug'], stdout=node_log, stderr=STDOUT, bufsize=1)
)
print(f'Setting up worker 1 in {w1_working_dir}')
worker1 = Worker(cwd=w1_working_dir, source_dir=source_bin_folder)
worker1.init_clean()
print('Initialized worker 1.')

# print('Starting worker 1 in background')
# worker1_proc = Popen([worker1_bin, '--help'], stdout=node_log, stderr=STDOUT, bufsize=1)

signal.pause()
