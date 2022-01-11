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

mod tls_ra_client;
mod tls_ra_server;

pub const _MAX_BUFFER_SIZE: u32 = 1024;

/// States the tcp stream content type.
#[derive(Copy, Clone, Debug)]
pub enum Opcode {
	ShieldingKey = 0,
	SigningKey = 1,
	State = 2,
}

impl From<u8> for Opcode {
	fn from(item: u8) -> Self {
		match item {
			0 => Opcode::ShieldingKey,
			1 => Opcode::SigningKey,
			2 => Opcode::State,
			_ => unimplemented!(),
		}
	}
}

impl Opcode {
	pub fn to_bytes(self) -> [u8; 1] {
		(self as u8).to_be_bytes()
	}
}

#[derive(Clone, Debug)]
pub struct TcpHeader {
	pub opcode: Opcode,
	pub payload_length: u64,
}

impl TcpHeader {
	fn new(opcode: Opcode, payload_length: u64) -> Self {
		Self { opcode, payload_length }
	}
}
