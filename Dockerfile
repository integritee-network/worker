FROM integritee/integritee-dev:0.1.12
LABEL maintainer="zoltan@integritee.network"

# By default we warp the service
ARG BINARY_FILE=integritee-service

COPY bin/enclave.signed.so /usr/local/bin/
COPY bin/${BINARY_FILE} /usr/local/bin/integritee

RUN chmod +x /usr/local/bin/integritee

WORKDIR /usr/local/bin
RUN touch spid.txt key.txt
RUN if [[ "x$BINARY_FILE" != "xintegritee-client" ]] ; then ./integritee init-shard; fi
RUN if [[ "x$BINARY_FILE" != "xintegritee-client" ]] ; then ./integritee shielding-key; fi
RUN if [[ "x$BINARY_FILE" != "xintegritee-client" ]] ; then ./integritee signing-key; fi
RUN if [[ "x$BINARY_FILE" != "xintegritee-client" ]] ; then ./integritee mrenclave > ~/mrenclave.b58; fi

# checks
RUN ldd /usr/local/bin/integritee && \
	/usr/local/bin/integritee --version

ENTRYPOINT ["/usr/local/bin/integritee"]
