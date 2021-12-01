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
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveSidechainOCallApi};
use itp_sgx_crypto::StateCrypto;
use its_primitives::traits::{
	Block as SidechainBlockT, ShardIdentifierFor, SignedBlock as SignedSidechainBlockT,
};
use its_state::{LastBlockExt, SidechainState};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::vec::Vec;

pub trait BlockImport<PB, SB>
where
	PB: ParentchainBlockTrait,
	SB: SignedSidechainBlockT,
{
	/// The verifier for of the respective consensus instance.
	type Verifier: Verifier<PB, SB, BlockImportParams = SB, Context = Self::Context>;

	/// Context needed to derive verifier relevant data.
	type SidechainState: SidechainState + LastBlockExt<SB::Block>;

	/// Provides the cryptographic functions for our the state encryption.
	type StateCrypto: StateCrypto;

	/// Context needed to derive verifier relevant data.
	type Context: EnclaveAttestationOCallApi + EnclaveSidechainOCallApi;

	/// Get a verifier instance.
	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier;

	/// Apply a state update by providing a mutating function.
	fn apply_state_update<F>(
		&self,
		shard: &ShardIdentifierFor<SB>,
		mutating_function: F,
	) -> Result<(), Error>
	where
		F: FnOnce(Self::SidechainState) -> Result<Self::SidechainState, Error>;

	/// Key that is used for state encryption.
	fn state_key(&self) -> Self::StateCrypto;

	/// Getter for the context.
	fn get_context(&self) -> &Self::Context;

	/// Cleanup task after import is done.
	fn cleanup(&self, signed_sidechain_block: &SB) -> Result<(), Error>;

	/// Import a sidechain block and mutate state by `apply_state_update`.
	fn import_block(
		&self,
		signed_sidechain_block: SB,
		parentchain_header: &PB::Header,
	) -> Result<(), Error> {
		let sidechain_block = signed_sidechain_block.block().clone();
		let shard = sidechain_block.shard_id();
		self.apply_state_update(&shard, |mut state| {
			let mut verifier = self.verifier(state.clone());

			let block_import_params = verifier.verify(
				signed_sidechain_block.clone(),
				parentchain_header,
				self.get_context(),
			)?;

			let update = state_update_from_encrypted(
				block_import_params.block().state_payload(),
				self.state_key(),
			)?;

			state.apply_state_update(&update).map_err(|e| Error::Other(e.into()))?;

			state.set_last_block(block_import_params.block());

			Ok(state)
		})?;

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

#[cfg(test)]
mod tests {
	/* use super::*;
	use itp_test::mock::onchain_mock::OnchainMock;
	use its_consensus_aura::AuraVerifier;
	use its_primitives::{
		traits::SignedBlock as SidechainBlockT, types::SignedBlock as SidechainBlock,
	};
	use its_state::SidechainDB as GenericSidechainDB;
	use sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
	use sp_core::{ed25519, H256};
	use sp_runtime::generic::SignedBlock as ParentchainBlock;

	type SidechainDB =
		GenericSidechainDB<<SidechainBlock as SidechainBlockT>::Block, SgxExternalities>;

	type AuthorityPair = ed25519::Pair;

	type TestAuraVerifier =
		AuraVerifier<AuthorityPair, ParentchainBlock, SidechainBlock, SidechainDB, OnchainMock>;

	struct MockKey {}

	impl StateCrypto for MockKey {
		type Error = std::error::Error;

		fn encrypt(&self, data: &mut [u8]) -> Result<(), Self::Error> {
			Ok(())
		}

		fn decrypt(&self, data: &mut [u8]) -> Result<(), Self::Error> {
			Ok(())
		}
	}

	#[test]
	fn import_block_works() {
		let mut state = SidechainDB::default();
	}

	struct BlockImportMock {}

	impl BlockImport<ParentchainBlock, SidechainBlock> for BlockImportMock {
		type Verifier = TestAuraVerifier;
		type SidechainState = SidechainDB;
		type StateCrypto = MockKey;
		type Context = OnchainMock;

		fn verifier(&self, state: Self::SidechainState) -> Self::Verifier {
			Verifier::default()
		}
	}  */
}
