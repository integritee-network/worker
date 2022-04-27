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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{error::WebSocketError, WebSocketResult};

pub type ConnectionId = usize;

/// Trait to generate IDs (nonce) for websocket connections.
pub trait GenerateConnectionId {
	fn next_id(&self) -> WebSocketResult<ConnectionId>;
}

pub struct ConnectionIdGenerator {
	current_id: RwLock<ConnectionId>,
}

const MIN_ID: usize = 10;

impl Default for ConnectionIdGenerator {
	fn default() -> Self {
		Self { current_id: RwLock::new(MIN_ID) }
	}
}

impl GenerateConnectionId for ConnectionIdGenerator {
	fn next_id(&self) -> WebSocketResult<ConnectionId> {
		let mut id_lock = self.current_id.write().map_err(|_| WebSocketError::LockPoisoning)?;
		*id_lock = id_lock.checked_add(1).unwrap_or(MIN_ID);
		Ok(*id_lock)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ws_server::{NEW_CONNECTIONS_LISTENER, SERVER_SIGNAL_TOKEN};

	#[test]
	fn next_id_works() {
		let id_generator = ConnectionIdGenerator::default();

		assert_eq!(11, id_generator.next_id().unwrap());
		assert_eq!(12, id_generator.next_id().unwrap());
		assert_eq!(13, id_generator.next_id().unwrap());
	}

	#[test]
	fn next_id_is_greater_than_default_tokens() {
		let id_generator = ConnectionIdGenerator::default();

		let first_id = id_generator.next_id().unwrap();

		assert!(NEW_CONNECTIONS_LISTENER < mio::Token(first_id));
		assert!(SERVER_SIGNAL_TOKEN < mio::Token(first_id));
	}
}
