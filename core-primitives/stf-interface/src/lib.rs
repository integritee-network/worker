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

//! Provides a state interface.
//! This allow to easily mock the stf and exchange it with another storage.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_node_api_metadata::NodeMetadataTrait;
use itp_node_api_metadata_provider::AccessNodeMetadata;
use itp_stf_primitives::traits::TrustedCallVerification;
use itp_types::{
	parentchain::{AccountId, BlockHash, BlockNumber, ParentchainCall, ParentchainId},
	Moment, ShardIdentifier,
};

#[cfg(feature = "mocks")]
pub mod mocks;
pub mod parentchain_pallet;
pub mod sudo_pallet;
pub mod system_pallet;

pub const SHARD_CREATION_HEADER_KEY: &str = "ShardCreationHeaderKey";

/// Interface to initialize a new state.
pub trait InitState<State, AccountId> {
	/// Initialize a new state for a given enclave account.
	fn init_state(enclave_account: AccountId) -> State;
}

/// Interface to query shard vault account for shard
pub trait ShardVaultQuery<S> {
	fn get_vault(state: &mut S) -> Option<(AccountId, ParentchainId)>;
}

/// Interface to query shard creation block information for shard on a specified parentchain
pub trait ShardCreationQuery<S> {
	fn get_shard_creation_info(state: &mut S) -> ShardCreationInfo;
}

/// Interface for all functions calls necessary to update an already
/// initialized state.
pub trait UpdateState<State, StateDiff> {
	/// Updates a given state for
	fn apply_state_diff(state: &mut State, state_diff: StateDiff);
	fn storage_hashes_to_update_on_block(
		parentchain_id: &ParentchainId,
		shard: &ShardIdentifier,
	) -> Vec<Vec<u8>>;
}

/// Interface to execute state mutating calls on a state.
pub trait StateCallInterface<TCS, State, NodeMetadataRepository>
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
{
	type Error;

	/// Execute a call on a specific state. Callbacks are added as an `OpaqueCall`.
	fn execute_call(
		state: &mut State,
		shard: &ShardIdentifier,
		call: TCS,
		calls: &mut Vec<ParentchainCall>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error>;

	/// to be executed before any TrustedCalls in this batch/block
	fn on_initialize(state: &mut State, now: Moment) -> Result<(), Self::Error>;

	/// to be executed after any TrustedCalls in this batch/block
	fn on_finalize(state: &mut State) -> Result<(), Self::Error>;
}

/// Interface to execute state reading getters on a state.
pub trait StateGetterInterface<G, S> {
	/// Execute a getter on a specific state.
	fn execute_getter(state: &mut S, getter: G) -> Option<Vec<u8>>;

	fn get_parentchain_mirror_state<V: Decode>(
		state: &mut S,
		parentchain_key: Vec<u8>,
		parentchain_id: &ParentchainId,
	) -> Option<V>;
}

/// Trait used to abstract the call execution.
pub trait ExecuteCall<NodeMetadataRepository>
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	type Error;

	/// Execute a call. Callbacks are added as an `OpaqueCall`.
	fn execute(
		self,
		calls: &mut Vec<ParentchainCall>,
		shard: &ShardIdentifier,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error>;

	/// Get storages hashes that should be updated for a specific call.
	fn get_storage_hashes_to_update(self, shard: &ShardIdentifier) -> Vec<Vec<u8>>;
}

/// Trait used to abstract the getter execution.
pub trait ExecuteGetter {
	/// Execute a getter.
	fn execute(self) -> Option<Vec<u8>>;
	/// Get storages hashes that should be updated for a specific getter.
	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>>;
}

#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct BlockMetadata {
	pub number: BlockNumber,
	pub hash: BlockHash,
	pub timestamp: Option<Moment>,
}

#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct ShardCreationInfo {
	pub integritee: Option<BlockMetadata>,
	pub target_a: Option<BlockMetadata>,
	pub target_b: Option<BlockMetadata>,
}

impl ShardCreationInfo {
	pub fn for_parentchain(&self, id: ParentchainId) -> Option<BlockMetadata> {
		match id {
			ParentchainId::Integritee => self.integritee,
			ParentchainId::TargetA => self.target_a,
			ParentchainId::TargetB => self.target_b,
		}
	}
}

pub fn parentchain_mirror_prefix(parentchain_id: &ParentchainId) -> String {
	format!("L1MirrorFor{:?}", *parentchain_id)
}

/// when we mirror opaque state from L1 to L2, we want to prefix the keys in order to avoid clashes
pub fn prefix_storage_keys_for_parentchain_mirror(
	state_diff_update: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
	parentchain_id: &ParentchainId,
) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
	state_diff_update
		.iter()
		.map(|(key, value)| {
			let mut prefixed_key = parentchain_mirror_prefix(parentchain_id).as_bytes().to_vec();
			prefixed_key.extend(key);
			(prefixed_key, value.clone())
		})
		.collect()
}
