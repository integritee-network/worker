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
use itp_types::{
	AccountData, AccountId, BlockHash, Index, SidechainBlockNumber, SidechainTimestamp as Timestamp,
};
pub trait SystemPalletAccountInterface<State> {
	fn get_account_nonce(&self, state: &mut State, account_id: &AccountId) -> Index;
	fn get_account_data(&self, state: &mut State, account: &AccountId) -> AccountData;
}

pub trait SystemPalletSidechainInterface<State, SidechainBlock> {
	fn set_timestamp(&self, state: &mut State, timestamp: &Timestamp);
	fn get_timestamp(&self, state: &mut State) -> Timestamp;
	fn set_last_block_hash(&self, state: &mut State, hash: &BlockHash);
	fn get_last_block_hash(&self, state: &mut State) -> BlockHash;
	fn set_block_number(&self, state: &mut State, number: &SidechainBlockNumber);
	fn get_block_number(&self, state: &mut State) -> SidechainBlockNumber;
	fn set_last_block(&self, state: &mut State, block: &SidechainBlock);
	fn get_last_block(&self, state: &mut State) -> Option<SidechainBlock>;
}
