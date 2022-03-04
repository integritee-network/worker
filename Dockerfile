FROM integritee/integritee-dev:0.1.9
LABEL maintainer="zoltan@integritee.network"

# By default we warp the service-dev
ARG BINARY_FILE=integritee-service-dev

RUN echo "Oh dang look at that ${BINARY_FILE}"

COPY ${BINARY_FILE} /usr/local/bin
RUN chmod +x /usr/local/bin/${BINARY_FILE}

# checks
RUN ldd /usr/local/bin/${BINARY_FILE} && \
	/usr/local/bin/${BINARY_FILE} --version

ENV entrypoint="/usr/local/bin/${BINARY_FILE}"

ENTRYPOINT ${entrypoint}