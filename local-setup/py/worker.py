import pathlib
import shutil
from subprocess import Popen, STDOUT

from typing.io import TextIO

from .helpers import run_piped_subprocess, setup_working_dir, mkdir_p


class Worker:
    def __init__(self,
                 worker_bin='./substratee-worker',
                 cwd='./',
                 source_dir='./'
                 ):
        """
        Initialize a worker ready for execution.

        Args:
            worker_bin (str): Path to the worker bin relative to `cwd` or as absolute path.
            cwd (str):  working directory of the worker.
            source_dir (str):   directory of the source binaries, which will be copied to cwd because
                                the rust worker looks for files relative to cwd.

        """
        self.cwd = cwd
        self.cli = [worker_bin]
        self.source_dir = source_dir
        # cache fields
        self._mrenclave = None

    def setup_cwd(self, source_files: str):
        mkdir_p(self.cwd)
        setup_working_dir(source_files, self.cwd)

    def init_clean(self):
        """ Purges all db files first and initializes the environment afterwards """
        self.purge()
        self.init()

    def init(self):
        """ Initializes the environment such the the worker can be run """
        print('Copying source files to working directory')
        self.setup_cwd(self.source_dir)

        print('Initializing worker')
        print(self.init_shard())
        print(self.write_signer_pub())
        print(self.write_shielding_pub())

    def init_shard(self, shard=None):
        """
        :param shard: Shard to be initialized. Use mrenclave if `None`.
        :return:
        """
        if not shard:
            shard = self.mrenclave()
        if self.check_shard_and_prompt_delete(shard):
            return 'Shard exists already, will not initialize.'

        return run_piped_subprocess(self.cli + ['init-shard', shard], cwd=self.cwd)

    def shard_exists(self, shard):
        return self._shard_path(shard).exists()

    def check_shard_and_prompt_delete(self, shard=None):
        """
        Checks if the shard exists and will prompt to delete it.
        If shard is none, this will just return.

         :return:
            exists: True if file exists at the end of this call. False otherwise.

        """
        if self.shard_exists(shard):
            should_purge = input('Do you want to purge existing the shard? [y, n]')
            if should_purge == 'y':
                self.purge_shard(shard)
                print(f'Deleted shard {shard}.')
                return False
            else:
                print('Leaving shard as is')
                return True
        else:
            return False

    def purge(self):
        """ Deletes the mrenclave shard and the chain_relay_db.bin """
        self.purge_shard()
        self.purge_chain_relay_db()
        return self

    def purge_shard(self, shard=None):
        if not shard:
            shard = self.mrenclave()

        if not self.shard_exists(shard):
            print('The shard to be purged does not exist.')
        else:
            shutil.rmtree(self._shard_path(shard))

    @staticmethod
    def purge_chain_relay_db():
        db = pathlib.Path('./chain_relay_db.bin')
        if db.exists():
            db.unlink()

    def mrenclave(self):
        """ Returns the mrenclave and caches it. """
        if not self._mrenclave:
            self._mrenclave = run_piped_subprocess(self.cli + ['mrenclave'], cwd=self.cwd)
        return self._mrenclave

    def write_shielding_pub(self):
        return run_piped_subprocess(self.cli + ['shielding-key'], cwd=self.cwd)

    def write_signer_pub(self):
        return run_piped_subprocess(self.cli + ['signing-key'], cwd=self.cwd)

    def _shard_path(self, shard):
        return pathlib.Path(f'{self.cwd}/shards/{shard}')

    def run_in_background(self, log_file: TextIO):
        return Popen(self.cli + ['run'], stdout=log_file, stderr=STDOUT, bufsize=1, cwd=self.cwd)
