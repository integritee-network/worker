#  How to run the multi-validateer docker setup

## Prerequisite

Make sure you have installed Docker with `docker-compose` (version > `1.25.0`). On Windows, this can be Docker Desktop with WSL 2 integration.

## Building the Docker containers

Run
```
COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker-compose build
```
in this folder to build the worker image. This will build the worker from source and tag it in an image called `integritee-worker:dev`.

## Running the docker setup

`docker-compose up` will start all services (node and workers), using the `integritee-worker:dev` images you've built in the previous step.

## Run the integration tests
Build with
```
COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker-compose -f docker-compose.yml -f integration-test.yml
```
and then run with
```
docker-compose -f docker-compose.yml -f integration-test.yml up --exit-code-from sidechain-integration-test
```

## Run the fork simulator
The fork simulation uses `pumba` which in turn uses the Linux traffic control (TC). This is only available on Linux hosts, not on Windows with WSL unfortunately.
Build the docker-compose setup with
```
COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker-compose -f docker-compose.yml -f fork-inducer.yml -f integration-test.yml build
```

This requires the docker BuildKit (docker version >= 18.09) and support for it in docker-compose (version >= 1.25.0)

Run the 2-worker setup with a fork inducer (pumba) that delays the traffic on worker 2
```
docker-compose -f docker-compose.yml -f fork-inducer.yml -f integration-test.yml up --exit-code-from sidechain-integration-test
```

This should show that the integration test fails, because we had an unhandled fork in the sidechain. Clean up the containers after each run with:
```
docker-compose -f docker-compose.yml -f fork-inducer.yml -f integration-test.yml down
```

We need these different compose files to separate the services that we're using. E.g. we want the integration test and fork simulator to be optional. The same could be solved using `profiles` - but that requires a more up-to-date version of `docker-compose`.

## FAQ
### What do I have to do to stop everything properly?
With `Ctrl-C` you stop the containers and with `docker-compose down` you clean up/remove the containers. Note that `docker-compose down` will also remove any logs docker has saved, since it will remove all the container context.

### What do I have to do if I make changes to the code?
You need to re-build the worker image, using `docker-compose build`.

### How can I change the log level?
You can change the environment variable `RUST_LOG=` in the `docker-compose.yml` for each worker individually.

### The log from the node are quite a nuisance. Why are they all together.
You can suppress the log output for a container by setting the logging driver. This can be set to either `none` (completely disables all logs), or `local` (docker will record the logs, depending on you docker-compose version, it will also log to `stdout`) in the `docker-compose.yml`:
```
logging:
    driver: local
```
Mind the indent. Explanations for all the logging drivers in `docker-compose` can be found [here](https://docs.docker.com/config/containers/logging/local/).