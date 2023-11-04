# sidechain dependency graph
cargo depgraph --features dcap,sidechain --include enclave-runtime,itp-types,ita-stf | dot -Tsvg > dependency-graph.svg
