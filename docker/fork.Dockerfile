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

### Build Pumba image with dockerize
##################################################
FROM gaiaadm/pumba AS fork-simulator-deployed
LABEL maintainer="zoltan@integritee.network"

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