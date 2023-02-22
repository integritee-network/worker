#  How to use the local-setup

## Prerequisite
- worker built with ` SGX_MODE=SW make`
- integritee-node built with `cargo build --release --features skip-ias-check`

In case you have
- a sgx hardware and compile the worker with `SGX_MODE=HW` (default mode)
- a valid intel IAS key (development key is fine)

you can omit the `--features skip-ias-check` when building the node, but you must not use the subcommand flag `--skip-ra` in the json file (see [`two-workers.json`](./config/two-workers.json)) you're using to start the worker.

## Steps
Adapt or create your own config file, as in the example of [`two-workers.json`](./config/two-workers.json). Be mindful of the ports in case you're running the script on a server multiple people are working on.

### Launch worker and node in terminal one
You can launch the workers and the node with:
```bash
./local-setup/launch.py ./local-setup/config/two-workers.json
```
wait a little until all workers have been launched. You can stop the worker and node simply by pressing `Ctrl + c`.

### Open a second terminal to show logs
```bash
cd local-setup
./tmux_logger.sh
```

You can remove the tmux session of the script by running
```bash
tmux kill-session -t integritee_logger
```
### Open a third terminal to run a demo
```bash
cd <worker directory>/cli
./demo_shielding_unshielding.sh -p 99xx -P 20xx
```
