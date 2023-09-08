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

use crate::error::{Error, Result};
use itp_enclave_bridge_storage::{EnclaveBridgeStorage, EnclaveBridgeStorageKeys};
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_types::{
	parentchain::{AccountId, ParentchainId},
	ShardSignerStatus,
};
use its_primitives::traits::{Block as SidechainBlockTrait, Header as HeaderTrait, SignedBlock};
use log::trace;
use sp_core::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;

type ShardIdentifierFor<SignedSidechainBlock> =
<<<SignedSidechainBlock as SignedBlock>::Block as SidechainBlockTrait>::HeaderType as HeaderTrait>::ShardIdentifier;

pub trait ValidateerFetch {
	fn current_validateers<
		Header: HeaderT<Hash = H256>,
		SignedSidechainBlock: its_primitives::traits::SignedBlock,
	>(
		&self,
		latest_header: &Header,
		shard: ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<Vec<AccountId>>;
	fn validateer_count<
		Header: HeaderT<Hash = H256>,
		SignedSidechainBlock: its_primitives::traits::SignedBlock,
	>(
		&self,
		latest_header: &Header,
		shard: ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<u64>;
}

impl<OnchainStorage: EnclaveOnChainOCallApi> ValidateerFetch for OnchainStorage {
	fn current_validateers<
		Header: HeaderT<Hash = H256>,
		SignedSidechainBlock: its_primitives::traits::SignedBlock,
	>(
		&self,
		header: &Header,
		shard: ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<Vec<AccountId>> {
		let shard_status: Vec<ShardSignerStatus> = self
			.get_storage_verified(
				EnclaveBridgeStorage::shard_status::<ShardIdentifierFor<SignedSidechainBlock>>(
					shard,
				),
				header,
				&ParentchainId::Integritee,
			)?
			.into_tuple()
			.1
			.ok_or_else(|| Error::Other("Could not get validateer count from chain"))?;
		trace!("fetched {} validateers for shard {:?}", shard_status.len(), shard);
		Ok(shard_status.iter().map(|sss: &ShardSignerStatus| sss.signer.clone()).collect())
	}

	fn validateer_count<
		Header: HeaderT<Hash = H256>,
		SignedSidechainBlock: its_primitives::traits::SignedBlock,
	>(
		&self,
		header: &Header,
		shard: ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<u64> {
		Ok(self.current_validateers::<Header, SignedSidechainBlock>(header, shard)?.len() as u64)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use itc_parentchain_test::ParentchainHeaderBuilder;
	use itp_test::mock::onchain_mock::{validateer_set, OnchainMock};
	use itp_types::ShardIdentifier;

	#[test]
	pub fn get_validateer_count_works() {
		let header = ParentchainHeaderBuilder::default().build();
		let shard = ShardIdentifier::default();
		let mock = OnchainMock::default().add_validateer_set(&header, shard, None);
		assert_eq!(
			mock.validateer_count::<itp_types::Header, its_primitives::types::SignedBlock>(
				&header, shard
			)
			.unwrap(),
			4u64
		);
	}

	#[test]
	pub fn get_validateer_set_works() {
		let header = ParentchainHeaderBuilder::default().build();
		let shard = ShardIdentifier::default();
		let mock = OnchainMock::default().add_validateer_set(&header, shard, None);

		let validateers = validateer_set();

		assert_eq!(
			mock.current_validateers::<itp_types::Header, its_primitives::types::SignedBlock>(
				&header, shard
			)
			.unwrap(),
			validateers
		);
	}
}
