# Copyright 2021 Integritee AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#           http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This is a multi-stage docker file, where the first stage is used
# for building and the second deploys the built application.

### Builder Stage
##################################################
FROM integritee/integritee-dev:0.1.9 AS builder
LABEL maintainer="zoltan@integritee.network"

# set environment variables
ENV SGX_SDK /opt/sgxsdk
ENV PATH "$PATH:${SGX_SDK}/bin:${SGX_SDK}/bin/x64:/root/.cargo/bin"
ENV PKG_CONFIG_PATH "${PKG_CONFIG_PATH}:${SGX_SDK}/pkgconfig"
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:${SGX_SDK}/sdk_libs"
ENV CARGO_NET_GIT_FETCH_WITH_CLI true
ENV SGX_MODE SW

COPY . /root/work/worker/
WORKDIR /root/work/worker

#RUN --mount=type=cache,target=/usr/local/cargo/registry \
#	--mount=type=cache,target=/root/work/worker/target \
#	make
RUN make

### Enclave Test Stage
##################################################
FROM builder AS enclave-test

WORKDIR /root/work/worker/bin

CMD ./integritee-service test --all


### Cargo Test Stage
##################################################
FROM builder AS cargo-test

WORKDIR /root/work/worker

CMD cargo test

### Base Runner Stage
##################################################
FROM ubuntu:20.04 AS runner

RUN apt update && apt install -y libssl-dev iproute2

COPY --from=powerman/dockerize /usr/local/bin/dockerize /usr/local/bin/dockerize


### Deployed CLI client
##################################################
FROM runner AS deployed-client
LABEL maintainer="zoltan@integritee.network"

ARG SCRIPT_DIR=/usr/local/worker-cli
ARG LOG_DIR=/usr/local/log

ENV SCRIPT_DIR ${SCRIPT_DIR}
ENV LOG_DIR ${LOG_DIR}

COPY --from=builder /root/work/worker/bin/integritee-cli /usr/local/bin
COPY ./cli/*.sh /usr/local/worker-cli/

RUN chmod +x /usr/local/bin/integritee-cli ${SCRIPT_DIR}/*.sh
RUN mkdir ${LOG_DIR}

RUN ldd /usr/local/bin/integritee-cli && \
	/usr/local/bin/integritee-cli --version

ENTRYPOINT ["/usr/local/bin/integritee-cli"]


### Deployed worker service
##################################################
FROM runner AS deployed-worker
LABEL maintainer="zoltan@integritee.network"

ENV SGX_SDK /opt/sgxsdk
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:${SGX_SDK}/lib64"

WORKDIR /usr/local/bin

COPY --from=builder /opt/sgxsdk/lib64 /opt/sgxsdk/lib64
COPY --from=builder /root/work/worker/bin/* ./

RUN touch spid.txt key.txt
RUN chmod +x /usr/local/bin/integritee-service
RUN ls -al /usr/local/bin

# checks
RUN ldd /usr/local/bin/integritee-service && \
	/usr/local/bin/integritee-service --version

ENTRYPOINT ["/usr/local/bin/integritee-service"]
