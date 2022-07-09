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

use log::debug;
use rustls::{Certificate, ClientCertVerified, DistinguishedNames, TLSError};
use webpki::DNSName;

/// Test Rustls verifier, disables ALL verification (do NOT use in production!)
pub struct NoCertVerifier {}

impl rustls::ServerCertVerifier for NoCertVerifier {
	fn verify_server_cert(
		&self,
		_: &rustls::RootCertStore,
		_: &[rustls::Certificate],
		_: webpki::DNSNameRef<'_>,
		_: &[u8],
	) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
		debug!("Certificate verification bypassed");
		Ok(rustls::ServerCertVerified::assertion())
	}
}

impl rustls::ClientCertVerifier for NoCertVerifier {
	fn client_auth_root_subjects(&self, _sni: Option<&DNSName>) -> Option<DistinguishedNames> {
		None
	}

	fn verify_client_cert(
		&self,
		_presented_certs: &[Certificate],
		_sni: Option<&DNSName>,
	) -> Result<ClientCertVerified, TLSError> {
		debug!("Certificate verification bypassed");
		Ok(rustls::ClientCertVerified::assertion())
	}
}
