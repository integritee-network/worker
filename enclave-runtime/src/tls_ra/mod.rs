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

//! Contains all logic of the state provisioning mechanism
//! including the remote attestation and tls / tcp connection part.

use codec::{Decode, Encode, MaxEncodedLen};

mod authentication;
pub mod seal_handler;
mod tls_ra_client;
mod tls_ra_server;

#[cfg(feature = "test")]
pub mod tests;

#[cfg(feature = "test")]
pub mod mocks;

/// Header of an accompanied payload. Indicates the
/// length an the type (opcode) of the following payload.
#[derive(Clone, Debug, Decode, Encode, MaxEncodedLen)]
pub struct TcpHeader {
	pub opcode: Opcode,
	pub payload_length: u64,
}

impl TcpHeader {
	fn new(opcode: Opcode, payload_length: u64) -> Self {
		Self { opcode, payload_length }
	}
}

/// Indicates the payload content type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Decode, Encode, MaxEncodedLen)]
pub enum Opcode {
	ShieldingKey,
	StateKey,
	State,
	LightClient,
}

impl From<u8> for Opcode {
	fn from(item: u8) -> Self {
		match item {
			0 => Opcode::ShieldingKey,
			1 => Opcode::StateKey,
			2 => Opcode::State,
			3 => Opcode::LightClient,
			_ => unimplemented!("Unsupported/unknown Opcode for MU-RA exchange"),
		}
	}
}

impl Opcode {
	pub fn to_bytes(self) -> [u8; 1] {
		(self as u8).to_be_bytes()
	}
}
