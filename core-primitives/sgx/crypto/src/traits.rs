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

//! Abstraction over the state crypto that is used in the enclave
use std::{fmt::Debug, vec::Vec};

pub trait StateCrypto {
	type Error: Debug;
	fn encrypt(&self, data: &mut [u8]) -> Result<(), Self::Error>;
	fn decrypt(&self, data: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait ShieldingCryptoEncrypt {
	type Error: Debug;
	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait ShieldingCryptoDecrypt {
	type Error: Debug;
	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait ToPubkey {
	type Error: Debug;
	type Pubkey;

	fn pubkey(&self) -> Result<Self::Pubkey, Self::Error>;
}
