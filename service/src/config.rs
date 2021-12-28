use clap::ArgMatches;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
	pub node_ip: String,
	pub node_port: String,
	pub worker_ip: String,
	/// Worker address that will be advertised on the parentchain. Should be used when the worker is running
	/// behind an nginx or docker server.
	pub external_worker_address: Option<String>,
	/// Port to directly communicate with the trusted tls server inside the enclave.
	pub trusted_worker_port: String,
	/// Port to the untrusted ws of the validateer.
	pub untrusted_worker_port: String,
	/// Port for mutual-remote attestation requests.
	pub mu_ra_port: String,
}

impl Config {
	pub fn new(
		node_ip: String,
		node_port: String,
		worker_ip: String,
		external_worker_address: Option<String>,
		trusted_worker_port: String,
		untrusted_worker_port: String,
		mu_ra_port: String,
	) -> Self {
		Self {
			node_ip,
			node_port,
			worker_ip,
			external_worker_address,
			trusted_worker_port,
			untrusted_worker_port,
			mu_ra_port,
		}
	}

	/// Returns the client url of the node (including ws://).
	pub fn node_url(&self) -> String {
		format!("{}:{}", self.node_ip, self.node_port)
	}

	pub fn trusted_worker_url_internal(&self) -> String {
		format!("{}:{}", self.worker_ip, self.trusted_worker_port)
	}

	/// Returns the trusted worker url that should be addressed by external clients.
	///
	/// In case external_address is set, it should be considered that the internal trusted server is a tls
	/// websocket and must have have a wss:// primary to the internal worker ip.
	pub fn trusted_worker_url_external(&self) -> String {
		match &self.external_worker_address {
			Some(external_address) => format!("{}:{}", external_address, self.trusted_worker_port),
			None => format!("wss://{}:{}", self.worker_ip, self.trusted_worker_port),
		}
	}

	pub fn untrusted_worker_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.untrusted_worker_port)
	}

	/// Returns the untrusted worker url that should be addressed by external clients.
	///
	/// In case external_address is set, it should be considered that the internal untrusted worker url
	/// must have a ws:// primary to the internal worker ip.
	pub fn untrusted_worker_url_external(&self) -> String {
		match &self.external_worker_address {
			Some(external_address) =>
				format!("{}:{}", external_address, self.untrusted_worker_port),
			None => format!("ws://{}:{}", self.worker_ip, self.untrusted_worker_port),
		}
	}

	pub fn mu_ra_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.mu_ra_port)
	}

	/// Returns the mutual remote attestion worker url that should be addressed by external workers.
	///
	/// In case external_address is set, it should be considered that the internal mu ra url must not have
	/// any ws(s):// primary to the internal worker ip.
	pub fn mu_ra_url_external(&self) -> String {
		match &self.external_worker_address {
			Some(external_address) => format!("{}:{}", external_address, self.mu_ra_port),
			None => format!("{}:{}", self.worker_ip, self.mu_ra_port),
		}
	}
}

impl From<&ArgMatches<'_>> for Config {
	fn from(m: &ArgMatches<'_>) -> Self {
		Self::new(
			m.value_of("node-server").unwrap_or("ws://127.0.0.1").into(),
			m.value_of("node-port").unwrap_or("9944").into(),
			if m.is_present("ws-external") { "0.0.0.0".into() } else { "127.0.0.1".into() },
			m.value_of("external-address").map(|e| e.to_string()),
			m.value_of("trusted-worker-port").unwrap_or("2000").into(),
			m.value_of("untrusted-worker-port").unwrap_or("2001").into(),
			m.value_of("mu-ra-port").unwrap_or("3443").into(),
		)
	}
}
