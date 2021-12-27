#  How to run the multi-validateer docker setup

## Prerequisite

### Build worker
Change to the parent directory of this repository.
```
# Optional: Make sure you have pulled the integritee dev docker image.
docker pull integritee/integritee-node-dev:1.0.6
# Run a bash shell in the docker environment. 
docker run -it -v $(pwd):/root/work integritee/integritee-dev:0.1.7 /bin/bash
# Change to the worker directory. ("work" is the directory in the container where your local directory is mounted.)
cd work/worker/
# build
CARGO_NET_GIT_FETCH_WITH_CLI=true SGX_MODE=SW make
```
> ℹ️  
> *Pro-Tip:* leave this container running and open a new terminal in case you have recompile. Otherwise, the build starts from the beginning everytime. 

### Create a docker image for the worker
Change to the bin directory of the worker.
```
cd worker/bin  
```
Build a docker image
```
docker build -t integritee-worker:dev .
```

## Start docker setup
Make sure you are inside the docker directory, where this file is located.
```
# if you follow this manual
cd ../docker
```
Start the magic:
```
docker-compose up
```

## FAQ
#### What do I have to do to stop everything properly?
With Ctrl-C you stop the containers and with `docker-compose down` you make sure that everything is shut down completely.

#### What do I have to do if I change something in the docker code?
You simply have to re-execute the make command and build the docker image again with the same docker build command. 
After that you are good to start the setup again with `docker-compose up`.

#### Is it difficult to change the log level?
Not at all! You can change the environment variables in the `docker-compose.yml` for each container individually 
as you are used to.

#### The log from the node are quite a nuisance. Why are they all together. 
You can suppress the logs for a container by setting the logging driver to none in the `docker-compose.yml`:
```
logging:
    driver: none
```
Mind the indent. 

Full example:
```
version: "3.3"
services:
  integritee-node:
    image: "integritee/integritee-node-dev:1.0.6"
    ports: 
     - 9944:9944
    command: --dev --rpc-methods unsafe --ws-external --rpc-external
    logging:
      driver: none
```




