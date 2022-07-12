#!/bin/bash
set -e

pushd ..

pushd bin
./integritee-service init-shard
./integritee-service mrenclave | tee ~/mrenclave.b58
popd


python3 local-setup/launch.py local-setup/simple-config.json &
PID=$!
echo $PID > ./benchmark.pid
echo "Benchmark PID: $PID"

sleep 40s

pushd bin
./integritee-cli -p 9979 -P 2079 trusted --direct --mrenclave $(cat ~/mrenclave.b58) benchmark 20 1000 -w
popd

sleep 10s

if test -f "./benchmark.pid"; then
    echo "Killing benchmark process"
    kill -s SIGTERM $(cat ./benchmark.pid)
    rm benchmark.pid
fi

popd
