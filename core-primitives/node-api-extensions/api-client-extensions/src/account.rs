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
use sp_runtime::MultiSignature;
use substrate_api_client::{Api, ExtrinsicParams, RpcClient};

/// ApiClient extension that contains some convenience methods around accounts.
pub trait AccountApi {
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32>;
	fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128>;
}

impl<P: Pair, Client: RpcClient, Params: ExtrinsicParams> AccountApi for Api<P, Client, Params>
where
	MultiSignature: From<P::Signature>,
{
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32> {
		Ok(self.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce))
	}

	fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128> {
		Ok(self.get_account_data(who)?.map_or_else(|| 0, |data| data.free))
	}
}
