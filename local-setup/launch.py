#!/usr/bin/env python3
"""
Launch a local dev setup consisting of one substraTEE-node and two workers.
"""
import atexit
import signal
import sys
from subprocess import Popen, STDOUT

from py.worker import Worker
from py.helpers import GracefulKiller

log_dir = '../log'
node_log = open(f'{log_dir}/node.log', 'w')
worker1_log = open(f'{log_dir}/worker1.log', 'w')
worker2_log = open(f'{log_dir}/worker2.log', 'w')

source_bin_folder = '../bin'
node_bin = '../../substraTEE-node/target/release/substratee-node'
w1_working_dir = '/tmp/w1'
w2_working_dir = '/tmp/w2'


def setup_worker(work_dir: str):
    print(f'Setting up worker in {work_dir}')
    worker = Worker(cwd=work_dir, source_dir=source_bin_folder)
    worker.init_clean()
    print('Initialized worker.')
    return worker


def main(processes):
    print('Starting substraTee-node-process in background')
    processes.append(
        Popen([node_bin, '--tmp', '--dev', '-lruntime=debug'], stdout=node_log, stderr=STDOUT, bufsize=1)
    )

    w1 = setup_worker(w1_working_dir)
    w2 = setup_worker(w2_working_dir)

    print('Starting worker 1 in background')
    processes.append(w1.run_in_background(log_file=worker1_log))
    print('Starting worker 2 in background')
    processes.append(w2.run_in_background(log_file=worker2_log))

    # keep script alive until terminated
    signal.pause()


if __name__ == '__main__':
    process_list = []
    killer = GracefulKiller(process_list)
    main(process_list)


