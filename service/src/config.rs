use clap::ArgMatches;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
	pub node_ip: String,
	pub node_port: String,
	pub worker_ip: String,
	/// Port to directly communicate with the trusted tls server inside the enclave.
	pub worker_rpc_port: String,
	/// Port to the untrusted ws of the validateer.
	pub untrusted_worker_port: String,
	/// Port for mutual-remote attestation requests.
	pub worker_mu_ra_port: String,
}

impl Config {
	pub fn new(
		node_ip: String,
		node_port: String,
		worker_ip: String,
		worker_rpc_port: String,
		untrusted_worker_port: String,
		worker_mu_ra_port: String,
	) -> Self {
		Self {
			node_ip,
			node_port,
			worker_ip,
			worker_rpc_port,
			untrusted_worker_port,
			worker_mu_ra_port,
		}
	}

	/// Returns the client url of the node (including ws://)
	pub fn node_url(&self) -> String {
		format!("{}:{}", self.node_ip, self.node_port)
	}

	pub fn trusted_worker_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.worker_rpc_port)
	}

	pub fn trusted_worker_url_for_client(&self) -> String {
		format!("wss://{}:{}", self.worker_ip, self.worker_rpc_port)
	}

	pub fn untrusted_worker_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.untrusted_worker_port)
	}

	pub fn untrusted_worker_url_for_client(&self) -> String {
		format!("ws://{}:{}", self.worker_ip, self.untrusted_worker_port)
	}

	pub fn mu_ra_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.worker_mu_ra_port)
	}

	pub fn mu_ra_url_for_client(&self) -> String {
		format!("{}:{}", self.worker_ip, self.worker_mu_ra_port)
	}
}

impl From<&ArgMatches<'_>> for Config {
	fn from(m: &ArgMatches<'_>) -> Self {
		Self::new(
			m.value_of("node-server").unwrap_or("ws://127.0.0.1").into(),
			m.value_of("node-port").unwrap_or("9944").into(),
			if m.is_present("ws-external") { "0.0.0.0".into() } else { "127.0.0.1".into() },
			m.value_of("worker-rpc-port").unwrap_or("2000").into(),
			m.value_of("untrusted-worker-port").unwrap_or("2001").into(),
			m.value_of("mu-ra-port").unwrap_or("3443").into(),
		)
	}
}
