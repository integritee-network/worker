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

use crate::{error::WebSocketError, WebSocketResult};
use rustls::NoClientAuth;
use std::{io::BufReader, string::ToString, sync::Arc, vec, vec::Vec};

pub fn make_config(cert: &str, key: &str) -> WebSocketResult<Arc<rustls::ServerConfig>> {
	let mut config = rustls::ServerConfig::new(NoClientAuth::new());

	let certs = load_certs(cert)?;
	let privkey = load_private_key(key)?;

	config
		.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
		.expect("Invalid key der");

	Ok(Arc::new(config))
}

fn load_certs(pem_content: &str) -> WebSocketResult<Vec<rustls::Certificate>> {
	let mut reader = BufReader::new(pem_content.as_bytes());
	rustls::internal::pemfile::certs(&mut reader)
		.map_err(|_| WebSocketError::InvalidCertificate("Failed to parse certificate".to_string()))
}

fn load_private_key(pem_content: &str) -> WebSocketResult<rustls::PrivateKey> {
	let rsa_keys = {
		let mut reader = BufReader::new(pem_content.as_bytes());

		rustls::internal::pemfile::rsa_private_keys(&mut reader).map_err(|_| {
			WebSocketError::InvalidPrivateKey("Failed to parse RSA private key".to_string())
		})?
	};

	let pkcs8_keys = {
		let mut reader = BufReader::new(pem_content.as_bytes());
		rustls::internal::pemfile::pkcs8_private_keys(&mut reader).map_err(|_| {
			WebSocketError::InvalidPrivateKey(
				"Invalid PKCS8 private key (encrypted keys are not supported)".to_string(),
			)
		})?
	};

	// prefer to load pkcs8 keys
	if !pkcs8_keys.is_empty() {
		Ok(pkcs8_keys[0].clone())
	} else if !rsa_keys.is_empty() {
		Ok(rsa_keys[0].clone())
	} else {
		Err(WebSocketError::InvalidPrivateKey("No viable private keys were given".to_string()))
	}
}
