use clap::ArgMatches;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
	pub node_ip: String,
	pub node_port: String,
	pub worker_ip: String,
	pub worker_rpc_port: String,
	/// listening port for the mutual-remote attestation requests
	pub worker_mu_ra_port: String,
	/// Todo: Is this deprecated? I can only see it in `enclave_perform_ra`
	pub ext_api_url: Option<String>,
}

impl Config {
	pub fn new(
		node_ip: String,
		node_port: String,
		worker_ip: String,
		worker_rpc_port: String,
		worker_mu_ra_port: String,
	) -> Self {
		Self {
			node_ip,
			node_port,
			worker_ip,
			worker_rpc_port,
			worker_mu_ra_port,
			ext_api_url: None,
		}
	}

	pub fn node_url(&self) -> String {
		format!("{}:{}", self.node_ip, self.node_port)
	}

	pub fn worker_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.worker_rpc_port)
	}

	pub fn mu_ra_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.worker_mu_ra_port)
	}

	pub fn set_ext_api_url(&mut self, url: String) {
		self.ext_api_url = Some(url)
	}
}

impl From<&ArgMatches<'_>> for Config {
	fn from(m: &ArgMatches<'_>) -> Self {
		Self::new(
			m.value_of("node-server").unwrap_or("ws://127.0.0.1").into(),
			m.value_of("node-port").unwrap_or("9944").into(),
			if m.is_present("ws-external") { "0.0.0.0".into() } else { "127.0.0.1".into() },
			m.value_of("worker-rpc-port").unwrap_or("2000").into(),
			m.value_of("mu-ra-port").unwrap_or("3443").into(),
		)
	}
}
