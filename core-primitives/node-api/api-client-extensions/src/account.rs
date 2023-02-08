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

use crate::ApiResult;
use itp_types::AccountId;
use sp_core::crypto::Pair;
use sp_rpc::number::NumberOrHex;
use sp_runtime::MultiSignature;
use substrate_api_client::{Api, BalancesConfig, ExtrinsicParams, FromHexString, RpcClient};

use codec::Decode;
use core::str::FromStr;

/// ApiClient extension that contains some convenience methods around accounts.
pub trait AccountApi {
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32>;
	// fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128>;
}

impl<P: Pair, Client: RpcClient, Params, Runtime> AccountApi for Api<P, Client, Params, Runtime>
where
	MultiSignature: From<P::Signature>,
	Params: ExtrinsicParams<Runtime::Index, Runtime::Hash>,
	Runtime: BalancesConfig,
	Runtime::Hash: FromHexString,
	Runtime::Index: Into<u32> + Decode,
	Runtime::Balance: TryFrom<NumberOrHex> + FromStr + Into<u128>,
	Runtime::AccountData: Into<u32>,
{
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32> {
		Ok(self.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce.into()))
	}

	// Please refer to https://github.com/integritee-network/worker/issues/1170, for why it got commented out.
	// fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128> {
	// 	Ok(self.get_account_info(who)?.map_or_else(|| 0, |info| info.data.free.into()))
	// }
}
