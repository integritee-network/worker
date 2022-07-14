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
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{RpcConnectionRegistry, RpcHash};
use itp_rpc::RpcResponse;
use std::{collections::HashMap, fmt::Debug};

type HashMapLock<K, V> = RwLock<HashMap<K, V>>;

pub struct ConnectionRegistry<Hash, Token>
where
	Hash: RpcHash,
	Token: Copy + Send + Sync + Debug,
{
	connection_map: HashMapLock<<Self as RpcConnectionRegistry>::Hash, (Token, RpcResponse)>,
}

impl<Hash, Token> ConnectionRegistry<Hash, Token>
where
	Hash: RpcHash,
	Token: Copy + Send + Sync + Debug,
{
	pub fn new() -> Self {
		Self::default()
	}

	#[cfg(test)]
	pub fn is_empty(&self) -> bool {
		self.connection_map.read().unwrap().is_empty()
	}
}

impl<Hash, Token> Default for ConnectionRegistry<Hash, Token>
where
	Hash: RpcHash,
	Token: Copy + Send + Sync + Debug,
{
	fn default() -> Self {
		ConnectionRegistry { connection_map: RwLock::new(HashMap::default()) }
	}
}

impl<Hash, Token> RpcConnectionRegistry for ConnectionRegistry<Hash, Token>
where
	Hash: RpcHash,
	Token: Copy + Send + Sync + Debug,
{
	type Hash = Hash;
	type Connection = Token;

	fn store(&self, hash: Self::Hash, connection: Self::Connection, rpc_response: RpcResponse) {
		let mut map = self.connection_map.write().unwrap();
		map.insert(hash, (connection, rpc_response));
	}

	fn withdraw(&self, hash: &Self::Hash) -> Option<(Self::Connection, RpcResponse)> {
		let mut map = self.connection_map.write().unwrap();
		map.remove(hash)
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;

	type TestRegistry = ConnectionRegistry<String, u64>;

	#[test]
	pub fn adding_element_with_same_hash_overwrite() {
		let registry = TestRegistry::new();

		let hash = "first".to_string();

		registry.store(hash.clone(), 1, dummy_rpc_response());
		registry.store(hash.clone(), 2, dummy_rpc_response());

		let connection_token = registry.withdraw(&hash).unwrap().0;
		assert_eq!(2, connection_token);
	}

	#[test]
	pub fn withdrawing_from_empty_registry_returns_none() {
		let registry = TestRegistry::new();

		assert!(registry.withdraw(&"hash".to_string()).is_none());
	}

	#[test]
	pub fn withdrawing_only_element_clears_registry() {
		let registry = TestRegistry::new();
		let hash = "first".to_string();

		registry.store(hash.clone(), 1, dummy_rpc_response());

		let connection = registry.withdraw(&hash);

		assert!(connection.is_some());
		assert!(registry.is_empty());
	}

	fn dummy_rpc_response() -> RpcResponse {
		RpcResponse { jsonrpc: String::new(), result: Default::default(), id: 1u32 }
	}
}
