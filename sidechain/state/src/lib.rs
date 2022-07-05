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

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

mod error;
mod impls;

pub use error::*;
pub use impls::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
mod sgx_reexports {
	pub use thiserror_sgx as thiserror;
}

use crate::error::Result;
use codec::{Decode, Encode};
use sgx_externalities::{SgxExternalitiesDiffType, SgxExternalitiesTrait};
use sidechain_primitives::{
	traits::Block as SidechainBlockTrait,
	types::{BlockHash, BlockNumber, Timestamp},
};
use sp_core::H256;
use sp_std::prelude::Vec;
use std::{marker::PhantomData, sync::Arc};

/// Sidechain wrapper and interface of the STF state.
///
/// TODO: In the course of refactoring the STF (#269), verify if this struct is even needed.
/// It might be that we could implement everything directly on `[SgxExternalities]`.
#[derive(Clone, Debug)]
pub struct SidechainDB<Block, Externalities, StorageKeyProvider> {
	/// Externalities
	ext: Externalities,
	storage_key_provider: Arc<StorageKeyProvider>,
	_phantom: PhantomData<Block>,
}

impl<Block, Externalities, StorageKeyProvider>
	SidechainDB<Block, Externalities, StorageKeyProvider>
{
	pub fn new(
		externalities: Externalities,
		storage_key_provider: Arc<StorageKeyProvider>,
	) -> Self {
		Self { ext: externalities, storage_key_provider, _phantom: Default::default() }
	}
}

/// Contains the necessary data to update the `SidechainDB` when importing a `SidechainBlock`.
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct StateUpdate {
	/// state hash before the `state_update` was applied.
	state_hash_apriori: H256,
	/// state hash after the `state_update` was applied.
	state_hash_aposteriori: H256,
	/// state diff applied to state with hash `state_hash_apriori`
	/// leading to state with hash `state_hash_aposteriori`
	state_update: SgxExternalitiesDiffType,
}

impl StateUpdate {
	/// get state hash before the `state_update` was applied.
	pub fn state_hash_apriori(&self) -> H256 {
		self.state_hash_apriori
	}
	/// get state hash after the `state_update` was applied.
	pub fn state_hash_aposteriori(&self) -> H256 {
		self.state_hash_aposteriori
	}
	/// reference to the `state_update`
	pub fn state_update(&self) -> &SgxExternalitiesDiffType {
		&self.state_update
	}

	/// create new `StatePayload` instance.
	pub fn new(apriori: H256, aposteriori: H256, update: SgxExternalitiesDiffType) -> StateUpdate {
		StateUpdate {
			state_hash_apriori: apriori,
			state_hash_aposteriori: aposteriori,
			state_update: update,
		}
	}
}

/// state hash abstraction
pub trait StateHash {
	fn hash(&self) -> H256;
}

/// Abstraction around the sidechain state.
pub trait SidechainState: Clone {
	type Externalities: SgxExternalitiesTrait + StateHash;

	type StateUpdate: Encode + Decode;

	type Hash;

	/// get the hash of the state
	fn state_hash(&self) -> Self::Hash;

	/// get a reference to the underlying externalities of the state
	fn ext(&self) -> &Self::Externalities;

	/// get a mutable reference to the underlying externalities of the state
	fn ext_mut(&mut self) -> &mut Self::Externalities;

	/// apply the state update to the state
	fn apply_state_update(&mut self, state_payload: &Self::StateUpdate) -> Result<()>;

	/// get a storage value by its full name
	fn get_with_name<V: Decode>(
		&self,
		module_prefix: &'static str,
		storage_prefix: &'static str,
	) -> Result<Option<V>>;

	/// set a storage value by its full name
	fn set_with_name<V: Encode>(
		&mut self,
		module_prefix: &'static str,
		storage_prefix: &'static str,
		value: V,
	) -> Result<()>;

	/// get a storage value by its storage hash
	fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

	/// set a storage value by its storage hash
	fn set(&mut self, key: &[u8], value: &[u8]);
}

/// trait to set and get the last sidechain block of the sidechain state
pub trait LastBlockExt<SidechainBlock: SidechainBlockTrait> {
	/// get the last block of the sidechain state
	fn get_last_block(&self) -> Result<Option<SidechainBlock>>;

	/// set the last block of the sidechain state
	fn set_last_block(&mut self, block: &SidechainBlock) -> Result<()>;
}

impl<SidechainBlock: SidechainBlockTrait, E, NodeMetadataProvider> LastBlockExt<SidechainBlock>
	for SidechainDB<SidechainBlock, E, NodeMetadataProvider>
where
	SidechainDB<SidechainBlock, E, NodeMetadataProvider>: SidechainState + SidechainSystemExt,
{
	fn get_last_block(&self) -> Result<Option<SidechainBlock>> {
		self.get_with_name("System", "LastBlock")
	}

	fn set_last_block(&mut self, block: &SidechainBlock) -> Result<()> {
		self.set_last_block_hash(&block.hash())?;
		self.set_with_name("System", "LastBlock", block)
	}
}

/// system extension for the `SidechainDB`
pub trait SidechainSystemExt {
	/// get the last block number of the sidechain state
	fn get_block_number(&self) -> Result<Option<BlockNumber>>;

	/// set the last block number of the sidechain state
	fn set_block_number(&mut self, number: &BlockNumber) -> Result<()>;

	/// get the last block hash of the sidechain state
	fn get_last_block_hash(&self) -> Result<Option<BlockHash>>;

	/// set the last block hash of the sidechain state
	fn set_last_block_hash(&mut self, hash: &BlockHash) -> Result<()>;

	/// get the timestamp of the sidechain state
	fn get_timestamp(&self) -> Result<Option<Timestamp>>;

	/// set the timestamp of the sidechain state
	fn set_timestamp(&mut self, timestamp: &Timestamp) -> Result<()>;
}

impl<T: SidechainState> SidechainSystemExt for T {
	fn get_block_number(&self) -> Result<Option<BlockNumber>> {
		self.get_with_name("System", "Number")
	}

	fn set_block_number(&mut self, number: &BlockNumber) -> Result<()> {
		self.set_with_name("System", "Number", number)
	}

	fn get_last_block_hash(&self) -> Result<Option<BlockHash>> {
		self.get_with_name("System", "LastHash")
	}

	fn set_last_block_hash(&mut self, hash: &BlockHash) -> Result<()> {
		self.set_with_name("System", "LastHash", hash)
	}

	fn get_timestamp(&self) -> Result<Option<Timestamp>> {
		self.get_with_name("System", "Timestamp")
	}

	fn set_timestamp(&mut self, timestamp: &Timestamp) -> Result<()> {
		self.set_with_name("System", "Timestamp", timestamp)
	}
}
