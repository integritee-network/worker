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

use crate::{
	config_provider::ProvideServerConfig,
	test::fixtures::{
		test_cert::get_test_certificate_chain, test_private_key::get_test_private_key,
	},
	WebSocketResult,
};
use rustls::{NoClientAuth, ServerConfig};
use std::sync::Arc;

pub struct TestServerConfigProvider;

impl ProvideServerConfig for TestServerConfigProvider {
	fn get_config(&self) -> WebSocketResult<Arc<ServerConfig>> {
		let mut config = rustls::ServerConfig::new(NoClientAuth::new());

		let certs = get_test_certificate_chain();
		let privkey = get_test_private_key();

		config
			.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
			.unwrap();

		Ok(Arc::new(config))
	}
}
