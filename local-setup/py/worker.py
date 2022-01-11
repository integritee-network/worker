import os
import pathlib
import shutil
import subprocess
from subprocess import Popen, STDOUT
from typing import Union, TextIO, IO

from .helpers import run_subprocess, setup_working_dir, mkdir_p


class Worker:
    def __init__(self,
                 worker_bin: str = './integritee-service',
                 cwd: str = './',
                 source_dir: str = './',
                 std_err: Union[None, int, IO] = STDOUT,
                 ):
        """
        Integritee-service wrapper.

        Args:
            worker_bin: Path to the worker bin relative to `cwd` or as absolute path.

            cwd:        working directory of the worker.

            source_dir: directory of the source binaries, which will be copied to cwd because
                        the rust worker looks for files relative to cwd.

            std_err:    Were the workers error output will be logged. Note: `std_out` is intended to be unconfigurable
                        because the prints from the rust worker are often intended to be used in scripts. Making this
                        configurable, could cause some weird errors.


        """
        self.cwd = cwd
        self.cli = [worker_bin]
        self.source_dir = source_dir
        self.std_err = std_err
        # cache fields
        self._mrenclave = None

    def setup_cwd(self):
        mkdir_p(self.cwd)
        setup_working_dir(self.source_dir, self.cwd)

    def init_clean(self):
        """ Purges all db files first and initializes the environment afterwards. """
        mkdir_p(self.cwd)
        print('Copying source files to working directory')
        self.setup_cwd()

        self.purge()
        self.init()

    def init(self):
        """ Initializes the environment such the the worker can be run. """
        print('Initializing worker')
        print(self.init_shard())
        print(self.write_signer_pub())
        print(self.write_shielding_pub())

    def init_shard(self, shard=None):
        """
        :param shard: Shard to be initialized. Use mrenclave if `None`.
        :return msg: `println!`'s generated by the rust worker.
        """
        if not shard:
            shard = self.mrenclave()
        if self.check_shard_and_prompt_delete(shard):
            return 'Shard exists already, will not initialize.'

        return run_subprocess(self.cli + ['init-shard', shard], stdout=subprocess.PIPE, stderr=self.std_err,
                              cwd=self.cwd)

    def shard_exists(self, shard):
        """ Checks if the shard in './shards/[shard]' exists

        :return: exists: True if exists, false otherwise.
        """
        return self._shard_path(shard).exists()

    def check_shard_and_prompt_delete(self, shard=None):
        """
        Checks if the shard exists and will prompt to delete it.
        If shard is none, this will just return.

         :return:
            exists: True if file exists at the end of this call. False otherwise.

        """
        if self.shard_exists(shard):
            should_purge = input('Do you want to purge existing the shards and sidechain db? [y, n]')
            if should_purge == 'y':
                self.purge_shards_and_sidechain_db()
                print(f'Deleted shard {shard}.')
                return False
            else:
                print('Leaving shard as is.')
                return True
        else:
            return False

    def purge(self):
        """ Deletes the light_client_db.bin, the shards and the sidechain_db
        """
        self.purge_last_slot_seal()
        self.purge_light_client_db()
        self.purge_shards_and_sidechain_db()
        return self

    def purge_shards_and_sidechain_db(self):
        if pathlib.Path(f'{self.cwd}/shards').exists():
            print(f'Purging shards')
            shutil.rmtree(pathlib.Path(f'{self.cwd}/shards'))

        if pathlib.Path(f'{self.cwd}/sidechain_db').exists():
            print(f'purging sidechain_db')
            shutil.rmtree(pathlib.Path(f'{self.cwd}/sidechain_db'))

    def purge_light_client_db(self):
        print(f'purging light_client_db')
        for db in pathlib.Path(self.cwd).glob('light_client_db.bin*'):
            print(f'remove: {db}')
            db.unlink()

    def purge_last_slot_seal(self):
        print(f'purging last_slot_seal')
        for db in pathlib.Path(self.cwd).glob('last_slot.bin'):
            print(f'remove: {db}')
            db.unlink()

    def mrenclave(self):
        """ Returns the mrenclave and caches it. """
        if not self._mrenclave:
            # `std_out` needs to be subProcess.PIPE here!
            self._mrenclave = run_subprocess(self.cli + ['mrenclave'], stdout=subprocess.PIPE, stderr=self.std_err,
                                             cwd=self.cwd)
        return self._mrenclave

    def write_shielding_pub(self):
        return run_subprocess(self.cli + ['shielding-key'], stdout=subprocess.PIPE, stderr=self.std_err, cwd=self.cwd)

    def write_signer_pub(self):
        return run_subprocess(self.cli + ['signing-key'], stdout=subprocess.PIPE, stderr=self.std_err, cwd=self.cwd)

    def sync_state(self, flags: [str] = None, skip_ra: bool = False):
        """ Returns the keys from another worker. """

        if skip_ra:
            subcommand_flags = ['request-keys', '--skip-ra']
        else:
            subcommand_flags = ['request-keys']

        return run_subprocess(self.cli + flags + subcommand_flags, stdout=subprocess.PIPE, stderr=self.std_err, cwd=self.cwd)

    def _shard_path(self, shard):
        return pathlib.Path(f'{self.cwd}/shards/{shard}')

    def run_in_background(self, log_file: TextIO, flags: [str] = None, subcommand_flags: [str] = None):
        """ Runs the worker in the background and writes to the supplied logfile.

        :return: process handle for the spawned background process.
        """

        # Todo: make this configurable
        env = dict(os.environ, RUST_LOG='info,ws=warn,sp_io=warn,'
                                        'substrate_api_client=warn,'
                                        'jsonrpsee_ws_client=warn,'
                                        'jsonrpsee_ws_server=warn,'
                                        'enclave_runtime=info,'
                                        'integritee_service=info,'
                                        'ita_stf=debug')

        return Popen(
            self._assemble_cmd(flags=flags, subcommand_flags=subcommand_flags),
            env=env,
            stdout=log_file,
            stderr=STDOUT,
            bufsize=1,
            cwd=self.cwd
        )

    def _assemble_cmd(self, flags: [str] = None, subcommand_flags: [str] = None):
        """ Assembles the cmd skipping None values. """
        cmd = self.cli
        if flags:
            cmd += flags
        cmd += ['run']
        if subcommand_flags:
            cmd += subcommand_flags
        return cmd
