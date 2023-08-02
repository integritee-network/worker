# integritee-worker

Integritee worker for Integritee [node](https://github.com/integritee-network/integritee-node) or [parachain](https://github.com/integritee-network/parachain)

This is part of [Integritee](https://integritee.network)

## Build and Run
Please see our [Integritee Book](https://docs.integritee.network/4-development/4.4-sdk) to learn how to build and run this.

To start multiple worker and a node with one simple command: Check out [this README](local-setup/README.md).

## Docker
See [docker/README.md](docker/README.md).

## Tests

There are 3 types of tests:
- cargo tests
- enclave tests
- integration tests

### Cargo Tests
Run
```
cargo test
```

### Enclave Tests
Run

```
make
./bin/integritee-service test --all
```

### Integration Tests
See [docker/README.md](docker/README.md)

## Direct calls scalability

For direct calls, a worker runs a web-socket server inside the enclave. An important factor for scalability is the transaction throughput of a single worker instance, which is in part defined by the maximum number of concurrent socket connections possible. On Linux by default, a process can have a maximum of `1024` concurrent file descriptors (show by `ulimit -n`).
If the web-socket server hits that limit, incoming connections will be declined until one of the established connections is closed. Permanently changing the `ulimit -n` value can be done in the `/etc/security/limits.conf` configuration file. See [this](https://linuxhint.com/permanently_set_ulimit_value/) guide for more information.
