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

use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use sgx_crypto_helper::{rsa3072::Rsa3072KeyPair, RsaKeyPair};
use std::vec::Vec;

/// Crypto key mock
///
/// mock implementation that does not encrypt
/// encrypt/decrypt return the input as is
#[derive(Clone)]
pub struct ShieldingCryptoMock {
	key: Rsa3072KeyPair,
}

impl Default for ShieldingCryptoMock {
	fn default() -> Self {
		ShieldingCryptoMock {
			key: Rsa3072KeyPair::new().expect("default RSA3072 key for shielding key mock"),
		}
	}
}

impl ShieldingCryptoEncrypt for ShieldingCryptoMock {
	type Error = itp_sgx_crypto::Error;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
		self.key.encrypt(data)
	}

	fn encrypt_to_hex_bytes(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
		self.key.encrypt(data)
	}
}

impl ShieldingCryptoDecrypt for ShieldingCryptoMock {
	type Error = itp_sgx_crypto::Error;

	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
		self.key.decrypt(data)
	}

	fn decrypt_from_hex_bytes(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
		self.key.decrypt(data)
	}
}
