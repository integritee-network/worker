#  How to use the local-setup

## Prerequisite
- worker built with `make`
- integritee-node built with `cargo build --release --features skip-ias-check`
(in case you have a valid intel key, you can omit the `--features skip-ias-check`)

## Steps
Adapt or create your own config file, as in the example of `simple-config.json`. Be mindful of the ports in case you're running the script on a server multiple people are working on.

### Launch worker and node in terminal one
You can launch the workers and the node with:
```bash
cd <worker directory>
./local-setup/launch.py ./local-setup/simple-config.json
```
wait a little until all workers have been launched. You can stop the worker and node simply by pressing `Ctrl + c`.

### Open a second terminal to show logs
```bash
cd <worker directory>/local-setup
# If you work with docker: exec into the running container:
docker exec -it [container-id] bash
cd work
# run the tmux logger script with:
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
