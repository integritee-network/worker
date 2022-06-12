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

use crate::{
	error::Result,
	traits::{StatePostProcessing, StfExecuteShieldFunds, StfExecuteTrustedCall},
};
use ita_stf::{AccountId, ShardIdentifier, TrustedOperation};
use itp_types::{Amount, GameId, OpaqueCall};
use sp_core::H256;
use sp_runtime::traits::Header as HeaderTrait;
use std::vec::Vec;

/// Mock for the StfExecutor.
#[derive(Default)]
pub struct StfExecutorMock;

impl StfExecuteTrustedCall for StfExecutorMock {
	fn execute_trusted_call<PH>(
		&self,
		_calls: &mut Vec<OpaqueCall>,
		_stf_call_signed: &TrustedOperation,
		_header: &PH,
		_shard: &ShardIdentifier,
		_post_processing: StatePostProcessing,
	) -> Result<Option<H256>>
	where
		PH: HeaderTrait<Hash = H256>,
	{
		todo!()
	}
}

impl StfExecuteShieldFunds for StfExecutorMock {
	fn execute_shield_funds(
		&self,
		_account: AccountId,
		_amount: Amount,
		_shard: &ShardIdentifier,
	) -> Result<H256> {
		todo!()
	}

	fn execute_new_game<ParentchainBlock>(
		&self,
		_game_id: GameId,
		_shard: &ShardIdentifier,
		_block: &ParentchainBlock,
	) -> Result<GameId> {
		todo!()
	}
}
