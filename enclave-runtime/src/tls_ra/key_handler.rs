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

use crate::error::{Error as EnclaveError, Result as EnclaveResult};
use codec::{Decode, Encode};
use itp_sgx_crypto::{Aes, AesSeal, Rsa3072Seal};
use itp_sgx_io::SealedIO;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use std::vec::Vec;

pub struct KeyHandler {}
pub trait SealKeys {
	fn seal_shielding_key(&mut self, bytes: &[u8]) -> EnclaveResult<()>;
	fn seal_signing_key(&mut self, bytes: &[u8]) -> EnclaveResult<()>;
}

pub trait UnsealKeys {
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>>;
	fn unseal_signing_key(&self) -> EnclaveResult<Vec<u8>>;
}

impl SealKeys for KeyHandler {
	fn seal_shielding_key(&mut self, bytes: &[u8]) -> EnclaveResult<()> {
		let key: Rsa3072KeyPair = serde_json::from_slice(bytes).map_err(|e| {
			error!("    [Enclave] Received Invalid RSA key");
			EnclaveError::Other(e.into())
		})?;
		Rsa3072Seal::seal(key)?;
		Ok(())
	}

	fn seal_signing_key(&mut self, mut bytes: &[u8]) -> EnclaveResult<()> {
		let aes = Aes::decode(&mut bytes)?;
		AesSeal::seal(Aes::new(aes.key, aes.init_vec))?;
		Ok(())
	}
}

impl UnsealKeys for KeyHandler {
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>> {
		let shielding_key = Rsa3072Seal::unseal()?;
		serde_json::to_vec(&shielding_key).map_err(|e| EnclaveError::Other(e.into()))
	}

	fn unseal_signing_key(&self) -> EnclaveResult<Vec<u8>> {
		Ok(AesSeal::unseal()?.encode())
	}
}
