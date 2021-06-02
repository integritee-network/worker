import pathlib
import shutil

from .helpers import run_piped_subprocess, setup_working_dir, mkdir_p


class Worker:
    def __init__(self,
                 worker_bin='./substratee-worker',
                 cwd='./'
                 ):
        """
        Initialize a worker ready for execution.

        Args:
            worker_bin (str): Path to the worker bin relative to `cwd` or as absolute path.
            cwd (str):  working directory of the worker. Relevant because the
                        rust worker saves and uses all files relative to `cwd`.

        """
        self.cwd = cwd
        self.cli = [worker_bin]

    def init_shard(self, shard=None):
        """
        :param shard: Shard to be initialized. Use mrenclave if `None`.
        :return:
        """
        if self.check_shard_and_prompt_delete(shard):
            return 'Shard exists already, will not initialize.'

        ret = ''
        if not shard:
            ret = run_piped_subprocess(self.cli + ['init-shard'], cwd=self.cwd)
        else:
            ret = run_piped_subprocess(self.cli + ['init-shard', shard], cwd=self.cwd)
        return ret

    def setup_cwd(self, source_files: str):
        mkdir_p(self.cwd)
        setup_working_dir(source_files, self.cwd)

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
            should_purge = input('Do you want to purge the shard? [y, n]')
            if should_purge == 'y':
                self.force_purge_shard(shard)
                print(f'Deleted shard {shard}.')
                return False
            else:
                print('Leaving shard as is')
                return True
        else:
            return False

    def force_purge_shard(self, shard):
        if not self.shard_exists(shard):
            print('The shard to be purged does not exist.')
        else:
            shutil.rmtree(self._shard_path(shard))

    def get_mrenclave(self):
        return run_piped_subprocess(self.cli + ['mrenclave'], cwd=self.cwd)

    def _shard_path(self, shard):
        return pathlib.Path(f'{self.cwd}/shards/{shard}')
