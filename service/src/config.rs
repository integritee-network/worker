/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use clap::ArgMatches;
use serde::{Deserialize, Serialize};

static DEFAULT_NODE_SERVER: &str = "ws://127.0.0.1";
static DEFAULT_NODE_PORT: &str = "9944";
static DEFAULT_TRUSTED_PORT: &str = "2000";
static DEFAULT_UNTRUSTED_PORT: &str = "2001";
static DEFAULT_MU_RA_PORT: &str = "3443";
static DEFAULT_METRICS_PORT: &str = "8787";
static DEFAULT_UNTRUSTED_HTTP_PORT: &str = "4545";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
	pub node_ip: String,
	pub node_port: String,
	pub worker_ip: String,
	/// Trusted worker address that will be advertised on the parentchain.
	pub trusted_external_worker_address: Option<String>,
	/// Port to directly communicate with the trusted tls server inside the enclave.
	pub trusted_worker_port: String,
	/// Untrusted worker address that will be returned by the dedicated trusted ws rpc call.
	pub untrusted_external_worker_address: Option<String>,
	/// Port to the untrusted ws of the validateer.
	pub untrusted_worker_port: String,
	/// Mutual remote attestation address that will be returned by the dedicated trusted ws rpc call.
	pub mu_ra_external_address: Option<String>,
	/// Port for mutual-remote attestation requests.
	pub mu_ra_port: String,
	/// Enable the metrics server
	pub enable_metrics_server: bool,
	/// Port for the metrics server
	pub metrics_server_port: String,
	/// Port for the untrusted HTTP server (e.g. for `is_initialized`)
	pub untrusted_http_port: String,
}

#[allow(clippy::too_many_arguments)]
impl Config {
	pub fn new(
		node_ip: String,
		node_port: String,
		worker_ip: String,
		trusted_external_worker_address: Option<String>,
		trusted_worker_port: String,
		untrusted_external_worker_address: Option<String>,
		untrusted_worker_port: String,
		mu_ra_external_address: Option<String>,
		mu_ra_port: String,
		enable_metrics_server: bool,
		metrics_server_port: String,
		untrusted_http_port: String,
	) -> Self {
		Self {
			node_ip,
			node_port,
			worker_ip,
			trusted_external_worker_address,
			trusted_worker_port,
			untrusted_external_worker_address,
			untrusted_worker_port,
			mu_ra_external_address,
			mu_ra_port,
			enable_metrics_server,
			metrics_server_port,
			untrusted_http_port,
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
	pub fn trusted_worker_url_external(&self) -> String {
		match &self.trusted_external_worker_address {
			Some(external_address) => external_address.to_string(),
			None => format!("wss://{}:{}", self.worker_ip, self.trusted_worker_port),
		}
	}

	pub fn untrusted_worker_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.untrusted_worker_port)
	}

	/// Returns the untrusted worker url that should be addressed by external clients.
	pub fn untrusted_worker_url_external(&self) -> String {
		match &self.untrusted_external_worker_address {
			Some(external_address) => external_address.to_string(),
			None => format!("ws://{}:{}", self.worker_ip, self.untrusted_worker_port),
		}
	}

	pub fn mu_ra_url(&self) -> String {
		format!("{}:{}", self.worker_ip, self.mu_ra_port)
	}

	/// Returns the mutual remote attestion worker url that should be addressed by external workers.
	pub fn mu_ra_url_external(&self) -> String {
		match &self.mu_ra_external_address {
			Some(external_address) => external_address.to_string(),
			None => format!("{}:{}", self.worker_ip, self.mu_ra_port),
		}
	}

	pub fn try_parse_metrics_server_port(&self) -> Option<u16> {
		self.metrics_server_port.parse::<u16>().ok()
	}

	pub fn try_parse_untrusted_http_server_port(&self) -> Option<u16> {
		self.untrusted_http_port.parse::<u16>().ok()
	}
}

impl From<&ArgMatches<'_>> for Config {
	fn from(m: &ArgMatches<'_>) -> Self {
		let trusted_port = m.value_of("trusted-worker-port").unwrap_or(DEFAULT_TRUSTED_PORT);
		let untrusted_port = m.value_of("untrusted-worker-port").unwrap_or(DEFAULT_UNTRUSTED_PORT);
		let mu_ra_port = m.value_of("mu-ra-port").unwrap_or(DEFAULT_MU_RA_PORT);
		let is_metrics_server_enabled = m.is_present("enable-metrics");
		let metrics_server_port = m.value_of("metrics-port").unwrap_or(DEFAULT_METRICS_PORT);
		let untrusted_http_port =
			m.value_of("untrusted-http-port").unwrap_or(DEFAULT_UNTRUSTED_HTTP_PORT);

		Self::new(
			m.value_of("node-server").unwrap_or(DEFAULT_NODE_SERVER).into(),
			m.value_of("node-port").unwrap_or(DEFAULT_NODE_PORT).into(),
			if m.is_present("ws-external") { "0.0.0.0".into() } else { "127.0.0.1".into() },
			m.value_of("trusted-external-address")
				.map(|url| add_port_if_necessary(url, trusted_port)),
			trusted_port.to_string(),
			m.value_of("untrusted-external-address")
				.map(|url| add_port_if_necessary(url, untrusted_port)),
			untrusted_port.to_string(),
			m.value_of("mu-ra-external-address")
				.map(|url| add_port_if_necessary(url, mu_ra_port)),
			mu_ra_port.to_string(),
			is_metrics_server_enabled,
			metrics_server_port.to_string(),
			untrusted_http_port.to_string(),
		)
	}
}

fn add_port_if_necessary(url: &str, port: &str) -> String {
	// [Option("ws(s)"), ip, Option(port)]
	match url.split(':').count() {
		3 => url.to_string(),
		2 => {
			if url.contains("ws") {
				// url is of format ws://127.0.0.1, no port added
				format!("{}:{}", url, port)
			} else {
				// url is of format 127.0.0.1:4000, port was added
				url.to_string()
			}
		},
		1 => format!("{}:{}", url, port),
		_ => panic!("Invalid worker url format in url input {:?}", url),
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use std::collections::HashMap;

	#[test]
	fn check_correct_config_assignment_for_empty_input() {
		let empty_args = ArgMatches::default();
		let config = Config::from(&empty_args);
		let expected_worker_ip = "127.0.0.1";

		assert_eq!(config.node_ip, DEFAULT_NODE_SERVER);
		assert_eq!(config.node_port, DEFAULT_NODE_PORT);
		assert_eq!(config.trusted_worker_port, DEFAULT_TRUSTED_PORT);
		assert_eq!(config.untrusted_worker_port, DEFAULT_UNTRUSTED_PORT);
		assert_eq!(config.mu_ra_port, DEFAULT_MU_RA_PORT);
		assert_eq!(config.worker_ip, expected_worker_ip);
		assert!(config.trusted_external_worker_address.is_none());
		assert!(config.untrusted_external_worker_address.is_none());
		assert!(config.mu_ra_external_address.is_none());
		assert!(!config.enable_metrics_server);
		assert_eq!(config.untrusted_http_port, DEFAULT_UNTRUSTED_HTTP_PORT);
	}

	#[test]
	fn worker_ip_is_set_correcty_for_set_ws_external_flag() {
		let expected_worker_ip = "0.0.0.0";

		let mut args = ArgMatches::default();
		args.args = HashMap::from([("ws-external", Default::default())]);
		let config = Config::from(&args);

		assert_eq!(config.worker_ip, expected_worker_ip);
	}

	#[test]
	fn check_correct_config_assignment_for_given_input() {
		let node_ip = "ws://12.1.58.1";
		let node_port = "111111";
		let trusted_ext_addr = "wss://1.1.1.2:700";
		let trusted_port = "7119";
		let untrusted_ext_addr = "ws://1.723.3.1:11";
		let untrusted_port = "9119";
		let mu_ra_ext_addr = "1.1.3.1:1000";
		let mu_ra_port = "99";
		let untrusted_http_port = "4321";

		let mut args = ArgMatches::default();
		args.args = HashMap::from([
			("node-server", Default::default()),
			("node-port", Default::default()),
			("ws-external", Default::default()),
			("trusted-external-address", Default::default()),
			("untrusted-external-address", Default::default()),
			("mu-ra-external-address", Default::default()),
			("mu-ra-port", Default::default()),
			("untrusted-worker-port", Default::default()),
			("trusted-worker-port", Default::default()),
			("untrusted-http-port", Default::default()),
		]);
		// Workaround because MatchedArg is private.
		args.args.get_mut("node-server").unwrap().vals = vec![node_ip.into()];
		args.args.get_mut("node-port").unwrap().vals = vec![node_port.into()];
		args.args.get_mut("trusted-external-address").unwrap().vals = vec![trusted_ext_addr.into()];
		args.args.get_mut("untrusted-external-address").unwrap().vals =
			vec![untrusted_ext_addr.into()];
		args.args.get_mut("mu-ra-external-address").unwrap().vals = vec![mu_ra_ext_addr.into()];
		args.args.get_mut("mu-ra-port").unwrap().vals = vec![mu_ra_port.into()];
		args.args.get_mut("untrusted-worker-port").unwrap().vals = vec![untrusted_port.into()];
		args.args.get_mut("trusted-worker-port").unwrap().vals = vec![trusted_port.into()];
		args.args.get_mut("untrusted-http-port").unwrap().vals = vec![untrusted_http_port.into()];

		let config = Config::from(&args);

		assert_eq!(config.node_ip, node_ip);
		assert_eq!(config.node_port, node_port);
		assert_eq!(config.trusted_worker_port, trusted_port);
		assert_eq!(config.untrusted_worker_port, untrusted_port);
		assert_eq!(config.mu_ra_port, mu_ra_port);
		assert_eq!(config.trusted_external_worker_address, Some(trusted_ext_addr.to_string()));
		assert_eq!(config.untrusted_external_worker_address, Some(untrusted_ext_addr.to_string()));
		assert_eq!(config.mu_ra_external_address, Some(mu_ra_ext_addr.to_string()));
		assert_eq!(config.untrusted_http_port, untrusted_http_port.to_string());
	}

	#[test]
	fn external_addresses_are_returned_correctly_if_not_set() {
		let trusted_port = "7119";
		let untrusted_port = "9119";
		let mu_ra_port = "99";
		let expected_worker_ip = "127.0.0.1";

		let mut args = ArgMatches::default();
		args.args = HashMap::from([
			("mu-ra-port", Default::default()),
			("untrusted-worker-port", Default::default()),
			("trusted-worker-port", Default::default()),
		]);
		// Workaround because MatchedArg is private.
		args.args.get_mut("mu-ra-port").unwrap().vals = vec![mu_ra_port.into()];
		args.args.get_mut("untrusted-worker-port").unwrap().vals = vec![untrusted_port.into()];
		args.args.get_mut("trusted-worker-port").unwrap().vals = vec![trusted_port.into()];

		let config = Config::from(&args);

		assert_eq!(
			config.trusted_worker_url_external(),
			format!("wss://{}:{}", expected_worker_ip, trusted_port)
		);
		assert_eq!(
			config.untrusted_worker_url_external(),
			format!("ws://{}:{}", expected_worker_ip, untrusted_port)
		);
		assert_eq!(config.mu_ra_url_external(), format!("{}:{}", expected_worker_ip, mu_ra_port));
	}

	#[test]
	fn external_addresses_are_returned_correctly_if_set() {
		let trusted_ext_addr = "wss://1.1.1.2:700";
		let untrusted_ext_addr = "ws://1.723.3.1:11";
		let mu_ra_ext_addr = "1.1.3.1:1000";

		let mut args = ArgMatches::default();
		args.args = HashMap::from([
			("trusted-external-address", Default::default()),
			("untrusted-external-address", Default::default()),
			("mu-ra-external-address", Default::default()),
		]);
		// Workaround because MatchedArg is private.
		args.args.get_mut("trusted-external-address").unwrap().vals = vec![trusted_ext_addr.into()];
		args.args.get_mut("untrusted-external-address").unwrap().vals =
			vec![untrusted_ext_addr.into()];
		args.args.get_mut("mu-ra-external-address").unwrap().vals = vec![mu_ra_ext_addr.into()];

		let config = Config::from(&args);

		assert_eq!(config.trusted_worker_url_external(), trusted_ext_addr);
		assert_eq!(config.untrusted_worker_url_external(), untrusted_ext_addr);
		assert_eq!(config.mu_ra_url_external(), mu_ra_ext_addr);
	}

	#[test]
	fn ensure_no_port_is_added_to_url_with_port() {
		let url = "ws://hello:4000";
		let port = "0";

		let resulting_url = add_port_if_necessary(url, port);

		assert_eq!(resulting_url, url);
	}

	#[test]
	fn ensure_port_is_added_to_url_without_port() {
		let url = "wss://hello";
		let port = "0";

		let resulting_url = add_port_if_necessary(url, port);

		assert_eq!(resulting_url, format!("{}:{}", url, port));
	}

	#[test]
	fn ensure_no_port_is_added_to_url_with_port_without_prefix() {
		let url = "hello:10001";
		let port = "012";

		let resulting_url = add_port_if_necessary(url, port);

		assert_eq!(resulting_url, url);
	}

	#[test]
	fn ensure_port_is_added_to_url_without_port_without_prefix() {
		let url = "hello_world";
		let port = "10";

		let resulting_url = add_port_if_necessary(url, port);

		assert_eq!(resulting_url, format!("{}:{}", url, port));
	}
}
