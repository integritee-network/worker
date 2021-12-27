FROM integritee/integritee-dev:0.1.7

RUN mv /usr/share/ca* /tmp && \
	rm -rf /usr/share/*  && \
	mv /tmp/ca-certificates /usr/share/ && \
	useradd -m -u 1000 -U -s /bin/sh -d /integritee integritee && \
	mkdir -p /integritee/.local/share/integritee-service && \
	chown -R integritee:integritee /integritee/.local && \
	ln -s /integritee/.local/share/integritee-service /data

COPY integritee-service enclave.signed.so key.txt spid.txt integritee-service end.rsa end.fullchain /usr/local/bin
WORKDIR /usr/local/bin
RUN chmod +x /usr/local/bin/integritee-service
RUN touch spid.txt key.txt
RUN integritee-service init-shard
RUN integritee-service shielding-key
RUN integritee-service signing-key
RUN integritee-service mrenclave > ~/mrenclave.b58

# checks
RUN ldd /usr/local/bin/integritee-service && \
	/usr/local/bin/integritee-service --version

#USER integritee
EXPOSE 30333 9933 9944 9615

CMD ["/usr/local/bin/integritee-service"]
