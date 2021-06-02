import subprocess
import shutil


def run_piped_subprocess(args, cwd='./'):
    """ Wrapper around subprocess that allows a less verbose call """
    return subprocess.run(args, stdout=subprocess.PIPE, cwd=cwd).stdout.decode('utf-8').strip()


def setup_working_dir(source_dir: str, target_dir: str):
    """ Setup the working dir such that the necessary files to run a worker are contained.

     Args:
         source_dir: the directory containing the files the be copied. Usually this is the substraTEE-worker/bin dir.
         target_dir: the working directory of the worker to be run.
     """

    files_to_copy = ['enclave.signed.so', 'key.txt', 'spid.txt', 'substratee-worker']
    [shutil.copy(f'{source_dir}/{f}', f'{target_dir}/{f}') for f in files_to_copy]


def mkdir_p(path):
    """ Surprisingly, there is no simple function to create a dir if it does not exist in python """
    return subprocess.run(['mkdir', '-p', path])
