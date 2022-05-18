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

use itp_sgx_crypto::{aes::Aes, ShieldingCrypto, StateCrypto};

#[derive(Clone)]
pub struct ShieldingCryptoMock {
	key: Aes,
}

impl Default for ShieldingCryptoMock {
	fn default() -> Self {
		ShieldingCryptoMock { key: Aes::new([1u8; 16], [0u8; 16]) }
	}
}

impl ShieldingCrypto for ShieldingCryptoMock {
	type Error = itp_sgx_crypto::Error;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
		let mut encrypted = Vec::<u8>::from(data);
		self.key.encrypt(encrypted.as_mut_slice())?;
		Ok(encrypted)
	}

	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
		let mut decrypted = Vec::<u8>::from(data);
		self.key.decrypt(decrypted.as_mut_slice())?;
		Ok(decrypted)
	}
}
