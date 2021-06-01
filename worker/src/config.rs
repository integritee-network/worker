use clap::ArgMatches;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
	pub node_ip: String,
	pub node_port: String,
	pub worker_ip: String,
	pub worker_rpc_port: String,
	/// Port the worker listens for the mutual-remote attestation requests
	pub worker_mu_ra_port: String,
	/// Todo: Is this deprecated? I can only see it in `enclave_perform_ra`
	pub ext_api_url: Option<String>,
}

impl Config {
	pub fn node_url(&self) -> String {
		format!("{}:{}", self.node_ip, self.node_port)
	}

	pub fn worker_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.worker_rpc_port)
	}

	pub fn mu_ra_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.worker_mu_ra_port)
	}
}

impl From<&ArgMatches<'_>> for Config {
	fn from(m: &ArgMatches<'_>) -> Self {
		Self {
			node_ip: m.value_of("node-server").unwrap_or("ws://127.0.0.1").into(),
			node_port: m.value_of("node-port").unwrap_or("9944").into(),
			worker_ip: if m.is_present("ws-external") {
				"0.0.0.0".into()
			} else {
				"127.0.0.1".into()
			},
			worker_rpc_port: m.value_of("worker-rpc-port").unwrap_or("2000").into(),
			worker_mu_ra_port: m.value_of("mu-ra-port").unwrap_or("3443").into(),
			ext_api_url: None,
		}
	}
}