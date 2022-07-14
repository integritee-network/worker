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

//! Abstraction around block import

use crate::{Error, Verifier};
use codec::Decode;
use itp_ocall_api::EnclaveSidechainOCallApi;
use itp_sgx_crypto::StateCrypto;
use its_state::{LastBlockExt, SidechainState};
use log::*;
use sidechain_primitives::traits::{
	Block as SidechainBlockTrait, BlockData, Header as HeaderTrait, ShardIdentifierFor,
	SignedBlock as SignedSidechainBlockTrait,
};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::vec::Vec;

pub trait BlockImport<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	/// The verifier for of the respective consensus instance.
	type Verifier: Verifier<
		ParentchainBlock,
		SignedSidechainBlock,
		BlockImportParams = SignedSidechainBlock,
		Context = Self::Context,
	>;

	/// Context needed to derive verifier relevant data.
	type SidechainState: SidechainState + LastBlockExt<SignedSidechainBlock::Block>;

	/// Provides the cryptographic functions for our the state encryption.
	type StateCrypto: StateCrypto;

	/// Context needed to derive verifier relevant data.
	type Context: EnclaveSidechainOCallApi;

	/// Get a verifier instance.
	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier;

	/// Apply a state update by providing a mutating function.
	fn apply_state_update<F>(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
		mutating_function: F,
	) -> Result<(), Error>
	where
		F: FnOnce(Self::SidechainState) -> Result<Self::SidechainState, Error>;

	/// Verify a sidechain block that is to be imported.
	fn verify_import<F>(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
		verifying_function: F,
	) -> Result<SignedSidechainBlock, Error>
	where
		F: FnOnce(Self::SidechainState) -> Result<SignedSidechainBlock, Error>;

	/// Key that is used for state encryption.
	fn state_key(&self) -> Result<Self::StateCrypto, Error>;

	/// Getter for the context.
	fn get_context(&self) -> &Self::Context;

	/// Import parentchain blocks up to and including the one we see in the sidechain block that
	/// is scheduled for import.
	///
	/// Returns the latest header. If no block was imported with the trigger,
	/// we return `last_imported_parentchain_header`.
	fn import_parentchain_block(
		&self,
		sidechain_block: &SignedSidechainBlock::Block,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header, Error>;

	/// Peek the parentchain import queue for the block that is associated with a given sidechain.
	/// Does not perform the import or mutate the queue.
	///
	/// Warning: Be aware that peeking the parentchain block means that it is not verified (that happens upon import).
	fn peek_parentchain_header(
		&self,
		sidechain_block: &SignedSidechainBlock::Block,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header, Error>;

	/// Cleanup task after import is done.
	fn cleanup(&self, signed_sidechain_block: &SignedSidechainBlock) -> Result<(), Error>;

	/// Import a sidechain block and mutate state by `apply_state_update`.
	fn import_block(
		&self,
		signed_sidechain_block: SignedSidechainBlock,
		parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header, Error> {
		let sidechain_block = signed_sidechain_block.block().clone();
		let shard = sidechain_block.header().shard_id();

		debug!(
			"Attempting to import sidechain block (number: {}, hash: {:?}, parentchain hash: {:?})",
			signed_sidechain_block.block().header().block_number(),
			signed_sidechain_block.block().hash(),
			signed_sidechain_block.block().block_data().layer_one_head()
		);

		let peeked_parentchain_header =
			self.peek_parentchain_header(&sidechain_block, parentchain_header)
				.unwrap_or_else(|e| {
					warn!("Could not peek parentchain block, returning latest parentchain block ({:?})", e);
					parentchain_header.clone()
				});

		let block_import_params = self.verify_import(&shard, |state| {
			let verifier = self.verifier(state);
			verifier.verify(
				signed_sidechain_block.clone(),
				&peeked_parentchain_header,
				self.get_context(),
			)
		})?;

		let latest_parentchain_header =
			self.import_parentchain_block(&sidechain_block, parentchain_header)?;

		let state_key = self.state_key()?;

		self.apply_state_update(&shard, |mut state| {
			let update = state_update_from_encrypted(
				block_import_params.block().block_data().encrypted_state_diff(),
				state_key,
			)?;

			state.apply_state_update(&update).map_err(|e| Error::Other(e.into()))?;

			state.set_last_block(block_import_params.block());

			Ok(state)
		})?;

		self.cleanup(&signed_sidechain_block)?;

		// Store block in storage.
		self.get_context().store_sidechain_blocks(vec![signed_sidechain_block])?;

		Ok(latest_parentchain_header)
	}
}

fn state_update_from_encrypted<Key: StateCrypto, StateUpdate: Decode>(
	encrypted: &[u8],
	key: Key,
) -> Result<StateUpdate, Error> {
	let mut payload: Vec<u8> = encrypted.to_vec();
	key.decrypt(&mut payload).map_err(|e| Error::Other(format!("{:?}", e).into()))?;

	Ok(Decode::decode(&mut payload.as_slice())?)
}
