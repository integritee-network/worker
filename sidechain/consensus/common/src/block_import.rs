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
use its_primitives::traits::{
	Block as SidechainBlockT, ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait,
};
use its_state::{LastBlockExt, SidechainState};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::vec::Vec;

pub trait BlockImport<ParentchainBlock, SidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait,
	SidechainBlock: SignedSidechainBlockTrait,
{
	/// The verifier for of the respective consensus instance.
	type Verifier: Verifier<
		ParentchainBlock,
		SidechainBlock,
		BlockImportParams = SidechainBlock,
		Context = Self::Context,
	>;

	/// Context needed to derive verifier relevant data.
	type SidechainState: SidechainState + LastBlockExt<SidechainBlock::Block>;

	/// Provides the cryptographic functions for our the state encryption.
	type StateCrypto: StateCrypto;

	/// Context needed to derive verifier relevant data.
	type Context: EnclaveSidechainOCallApi;

	/// Get a verifier instance.
	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier;

	/// Apply a state update by providing a mutating function.
	fn apply_state_update<F>(
		&self,
		shard: &ShardIdentifierFor<SidechainBlock>,
		mutating_function: F,
	) -> Result<(), Error>
	where
		F: FnOnce(Self::SidechainState) -> Result<Self::SidechainState, Error>;

	/// Key that is used for state encryption.
	fn state_key(&self) -> Self::StateCrypto;

	/// Getter for the context.
	fn get_context(&self) -> &Self::Context;

	/// Import parentchain blocks up to and including the one we see in the sidechain block that
	/// is scheduled for import.
	///
	/// Returns the latest header. If no block was imported with the trigger,
	/// we return `last_imported_parentchain_header`.
	fn import_parentchain_block(
		&self,
		sidechain_block: &SidechainBlock::Block,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header, Error>;

	/// Cleanup task after import is done.
	fn cleanup(&self, signed_sidechain_block: &SidechainBlock) -> Result<(), Error>;

	/// Handles the cases where the sidechain block import failed.
	fn handle_import_error(
		&self,
		signed_sidechain_block: &SidechainBlock,
		error: Error,
	) -> Result<(), Error>;

	/// Handles the cases where the sidechain block import failed.
	fn handle_import_error(&self, signed_sidechain_block: &SB, error: Error) -> Result<(), Error>;

	/// Import a sidechain block and mutate state by `apply_state_update`.
	fn import_block(
		&self,
		signed_sidechain_block: SidechainBlock,
		parentchain_header: &ParentchainBlock::Header,
	) -> Result<(), Error> {
		let sidechain_block = signed_sidechain_block.block().clone();
		let shard = sidechain_block.shard_id();

		let latest_parentchain_header =
			self.import_parentchain_block(&sidechain_block, parentchain_header)?;

		if let Err(error) = self.apply_state_update(&shard, |mut state| {
			let mut verifier = self.verifier(state.clone());

			let block_import_params = verifier.verify(
				signed_sidechain_block.clone(),
				&latest_parentchain_header,
				self.get_context(),
			)?;

			let update = state_update_from_encrypted(
				block_import_params.block().state_payload(),
				self.state_key(),
			)?;

			state.apply_state_update(&update).map_err(|e| Error::Other(e.into()))?;

			state.set_last_block(block_import_params.block());

			Ok(state)
		}) {
			self.handle_import_error(&signed_sidechain_block, error)?;
		}

		self.cleanup(&signed_sidechain_block)?;

		// Store block in storage.
		self.get_context().store_sidechain_blocks(vec![signed_sidechain_block])?;

		Ok(())
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
