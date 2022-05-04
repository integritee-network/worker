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

COPY . /root/work/worker/

ENV CARGO_NET_GIT_FETCH_WITH_CLI true
ENV SGX_MODE SW

WORKDIR /root/work/worker
RUN make

WORKDIR /root/work/worker/bin
RUN touch spid.txt key.txt


### Dockerize installation stage
##################################################
FROM ubuntu:20.04 AS dockerize

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y curl gpg
RUN curl --version
# Curl already installed in base image
# RUN apt update && apt install -y curl && rm -rf /var/lib/apt/lists/*

RUN curl -sfL https://github.com/powerman/dockerize/releases/download/v0.11.5/dockerize-`uname -s`-`uname -m` | install /dev/stdin /usr/local/bin/dockerize

# Verify signature of 'dockerize'

RUN curl -sfL https://powerman.name/about/Powerman.asc | gpg --import
RUN curl -sfL https://github.com/powerman/dockerize/releases/download/v0.11.5/dockerize-`uname -s`-`uname -m`.asc >dockerize.asc
RUN gpg --verify dockerize.asc /usr/local/bin/dockerize


### Deployment stage
##################################################
FROM ubuntu:20.04

WORKDIR /usr/local/bin

RUN apt update && apt install -y libssl-dev

COPY --from=builder /opt/sgxsdk/lib64 /opt/sgxsdk/lib64
COPY --from=builder /root/work/worker/bin/* ./
COPY --from=dockerize /usr/local/bin/dockerize ./

ENV SGX_SDK /opt/sgxsdk
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:${SGX_SDK}/lib64"

RUN chmod +x /usr/local/bin/integritee-service
RUN ls -al /usr/local/bin

# checks
RUN ldd /usr/local/bin/integritee-service && \
	/usr/local/bin/integritee-service --version

ENTRYPOINT ["/usr/local/bin/integritee-service"]
