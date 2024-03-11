# Raffle Demo:

## Preliminary

Run the local setup with one worker

```bash
./local-setup/launch.py ./local-setup/config/one-worker.json
```

# Setup

```bash
NPORT=9944
NODEURL=ws://127.0.0.1

WORKER1PORT=2000
WORKER1URL=wss://127.0.0.1

CLIENT_BIN=../bin/integritee-cli

RAFFLE_INDEX=0

CLIENT="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"

# Query workers
$CLIENT list-workers
```

Assign mrenclave from above list-workers command to env var.

```bash
MRENCLAVE=
```

# Create Raffle

Create a raffle with Alice

```bash
WINNERS_COUNT=2
$CLIENT trusted --mrenclave ${MRENCLAVE} --direct add-raffle //Alice ${WINNERS_COUNT}
```

# Have some users register for the raffle

```bash
USER_COUNT=50

for ((i=1; i<=USER_COUNT; i++)); do
  # Register users in the background
  $CLIENT trusted --mrenclave "$MRENCLAVE" --direct register-for-raffle "//RaffleUser${i}" "$RAFFLE_INDEX" &
done

# await background processes

wait
echo "Registered ${USER_COUNT} users"
```

# Draw winners

Only the Raffle creator, //Alice, may draw the winners

```bash
$CLIENT trusted --mrenclave ${MRENCLAVE} --direct draw-winners //Alice ${RAFFLE_INDEX}
```

# Get and verify the registration

Get the merkle proof of a raffle user and verify it on chain.

```bash
$CLIENT trusted --mrenclave ${MRENCLAVE} --direct get-and-verify-registration-proof //RaffleUser10 ${RAFFLE_INDEX}
```