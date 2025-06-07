Manually check certificate hierarchy for the exact domain the teeracle will query.
Find the root CA and add its PEM to this directory and then provide it in
`root_certificates_content()` in `oracle_sources`.