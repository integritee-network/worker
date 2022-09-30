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

use crate::{helpers::get_storage_value, Stf};
use codec::Encode;
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_interface::system_pallet::SystemPalletSidechainInterface;
use itp_storage::storage_value_key;
use itp_types::{BlockHash, SidechainBlockNumber, SidechainTimestamp as Timestamp};
use its_primitives::traits::Block as SidechainBlockTrait;
use std::prelude::v1::*;

impl<Call, Getter, State, SidechainBlock> SystemPalletSidechainInterface<State, SidechainBlock>
	for Stf<Call, Getter, State>
where
	State: SgxExternalitiesTrait,
	SidechainBlock: SidechainBlockTrait,
{
	fn set_timestamp(state: &mut State, timestamp: &Timestamp) {
		state.execute_with(|| {
			sp_io::storage::set(&storage_value_key("System", "Timestamp"), &timestamp.encode())
		});
	}

	fn get_timestamp(state: &mut State) -> Timestamp {
		state
			.execute_with(|| get_storage_value("System", "Timestamp"))
			.unwrap_or_default()
	}

	fn set_last_block_hash(state: &mut State, hash: &BlockHash) {
		state.execute_with(|| {
			sp_io::storage::set(&storage_value_key("System", "LastHash"), &hash.encode())
		})
	}

	fn get_last_block_hash(state: &mut State) -> BlockHash {
		state
			.execute_with(|| get_storage_value("System", "LastHash"))
			.unwrap_or_default()
	}

	fn set_block_number(state: &mut State, number: &SidechainBlockNumber) {
		state.execute_with(|| {
			sp_io::storage::set(&storage_value_key("System", "Number"), &number.encode())
		})
	}

	fn get_block_number(state: &mut State) -> SidechainBlockNumber {
		state.execute_with(|| get_storage_value("System", "Number")).unwrap_or_default()
	}

	fn set_last_block(state: &mut State, block: &SidechainBlock) {
		state.execute_with(|| {
			sp_io::storage::set(&storage_value_key("System", "LastBlock"), &block.encode())
		})
	}

	fn get_last_block(state: &mut State) -> Option<SidechainBlock> {
		state.execute_with(|| get_storage_value("System", "LastBlock"))
	}
}
