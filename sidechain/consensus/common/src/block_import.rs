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
use itp_sgx_crypto::StateCrypto;
use its_primitives::traits::{
	Block as SidechainBlock, ShardIdentifierFor, SignedBlock as SignedSidechainBlock,
};
use its_state::{LastBlockExt, SidechainState};
use sp_runtime::traits::Block as ParentchainBlock;
use std::vec::Vec;

pub trait BlockImport<PB, SB>
where
	PB: ParentchainBlock,
	SB: SignedSidechainBlock,
{
	/// the verifier for of the respective consensus instance
	type Verifier: Verifier<PB, SB, BlockImportParams = SB, Context = Self::Context>;

	/// context needed to derive verifier relevant data
	type SidechainState: SidechainState + LastBlockExt<SB::Block>;

	/// provides the cryptographic functions for our the state encryption
	type StateCrypto: StateCrypto;

	/// context needed to derive verifier relevant data
	type Context;

	/// get a verifier instance
	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier;

	/// get the sidechain state
	fn get_state(&self, shard: &ShardIdentifierFor<SB>) -> Result<Self::SidechainState, Error>;

	/// set the sidechain state
	fn set_state(
		&mut self,
		state: Self::SidechainState,
		shard: &ShardIdentifierFor<SB>,
	) -> Result<(), Error>;

	/// key that is used for state encryption
	fn state_key() -> Result<Self::StateCrypto, Error>;

	/// import the block
	fn import_block(
		&mut self,
		sidechain_block: SB,
		parentchain_header: &PB::Header,
		ctx: &Self::Context,
	) -> Result<(), Error> {
		let shard = sidechain_block.block().shard_id();
		let mut state = self.get_state(&shard)?;

		let mut verifier = self.verifier(state.clone());

		let block_import_params = verifier.verify(sidechain_block, parentchain_header, ctx)?;

		let update = state_update_from_encrypted(
			block_import_params.block().state_payload(),
			Self::state_key()?,
		)?;

		state.apply_state_update(&update).map_err(|e| Error::Other(e.into()))?;

		state.set_last_block(block_import_params.block());

		self.set_state(state, &shard)?;

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
