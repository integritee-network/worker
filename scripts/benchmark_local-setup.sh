#!/bin/bash
set -e

pushd ..

pushd bin
./integritee-service mrenclave | tee ~/mrenclave.b58
popd

ulimit -S -n 4096

python3 local-setup/launch.py local-setup/benchmark-config.json &
PID=$!
echo $PID > ./benchmark.pid
echo "Benchmark PID: $PID"

sleep 40s

pushd bin
./integritee-cli -p 9930 -P 2030 trusted --direct --mrenclave "$(cat ~/mrenclave.b58)" benchmark 20 100 -w
popd

sleep 10s

if test -f "./benchmark.pid"; then
    echo "Killing benchmark process"
    kill -s SIGTERM "$(cat ./benchmark.pid)"
    rm benchmark.pid
fi

popd
