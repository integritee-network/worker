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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{error::WebSocketResult, tls_common::make_config};
use rustls::ServerConfig;
use std::{string::String, sync::Arc};

/// Trait to provide a Rustls server config.
pub trait ProvideServerConfig: Send + Sync {
	fn get_config(&self) -> WebSocketResult<Arc<rustls::ServerConfig>>;
}

pub struct FromFileConfigProvider {
	private_key_path: String,
	certificates_path: String,
}

impl FromFileConfigProvider {
	pub fn new(private_key_path: String, certificates_path: String) -> Self {
		Self { private_key_path, certificates_path }
	}
}

impl ProvideServerConfig for FromFileConfigProvider {
	fn get_config(&self) -> WebSocketResult<Arc<ServerConfig>> {
		make_config(self.certificates_path.as_str(), self.private_key_path.as_str())
	}
}
