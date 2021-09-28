#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

mod error;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
mod impls;

pub use error::*;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub use impls::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
mod sgx_reexports {
	pub use sp_io_sgx as sp_io;
	pub use thiserror_sgx as thiserror;
}

use codec::{Decode, Encode};
use its_primitives::traits::Block as SidechainBlockT;
use sgx_externalities::{SgxExternalitiesDiffType, SgxExternalitiesTrait};
use sp_core::H256;
use sp_std::prelude::Vec;
use std::marker::PhantomData;

#[derive(Clone, Debug, Default, Encode, Decode, PartialEq, Eq)]
pub struct SidechainDB<Block, E> {
	/// Externalities
	pub ext: E,
	_phantom: PhantomData<Block>,
}

impl<Block, E> SidechainDB<Block, E> {
	pub fn new(externalities: E) -> Self {
		Self { ext: externalities, _phantom: Default::default() }
	}
}

/// Contains the necessary data to update the `SidechainDB` when importing a `SidechainBlock`.
#[cfg_attr(feature = "sgx", derive(Encode, Decode))]
#[derive(PartialEq, Eq, Clone, Debug)]
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

	/// apply the state update to the state
	fn apply_state_update(&mut self, state_payload: &Self::StateUpdate) -> Result<(), Error>;

	/// get a storage value by its full name
	fn get_with_name<V: Decode>(&self, module_prefix: &str, storage_prefix: &str) -> Option<V>;

	/// set a storage value by its full name
	fn set_with_name<V: Encode>(&mut self, module_prefix: &str, storage_prefix: &str, value: V);

	/// get a storage value by its storage hash
	fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

	/// set a storage value by its storage hash
	fn set(&mut self, key: &[u8], value: &[u8]);
}

/// system extension for the `SidechainDB`
pub trait SidechainSystemExt<SB: SidechainBlockT> {
	/// get the last block of the sidechain state
	fn get_last_block(&self) -> Option<SB>;

	/// set the last block of the sidechain state
	fn set_last_block(&mut self, block: &SB);
}

impl<SB: SidechainBlockT, E> SidechainSystemExt<SB> for SidechainDB<SB, E>
where
	SidechainDB<SB, E>: SidechainState,
{
	fn get_last_block(&self) -> Option<SB> {
		self.get_with_name("System", "LastBlock")
	}

	fn set_last_block(&mut self, block: &SB) {
		self.set_with_name("System", "LastBlock", block)
	}
}
