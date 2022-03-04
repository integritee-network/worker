FROM integritee/integritee-dev:0.1.9
LABEL maintainer="zoltan@integritee.network"

# By default we warp the service-dev
ARG BINARY_FILE=integritee-service-dev

RUN echo "Oh dang look at that ${BINARY_FILE}"

COPY ${BINARY_FILE} /usr/local/bin/integritee
RUN chmod +x /usr/local/bin/integritee

# checks
RUN ldd /usr/local/bin/integritee && \
	/usr/local/bin/integritee --version

ENTRYPOINT ["/usr/local/bin/integritee"]