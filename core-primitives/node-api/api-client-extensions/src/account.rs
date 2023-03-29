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
use itp_types::parentchain::{AccountData, AccountId, Balance, Hash, Index};
use sp_core::crypto::Pair;
use sp_runtime::MultiSignature;
use substrate_api_client::GetAccountInformation;

/// ApiClient extension that contains some convenience methods around accounts.
pub trait AccountApi {
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<Index>;
	fn get_free_balance(&self, who: &AccountId) -> ApiResult<Balance>;
}

impl<Api> AccountApi for Api
where
	Api: GetAccountInformation<AccountId, Index = Index, AccountData = AccountData>,
{
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<Index> {
		Ok(self.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce.into()))
	}

	fn get_free_balance(&self, who: &AccountId) -> ApiResult<Balance> {
		Ok(self.get_account_info(who)?.map_or_else(|| 0, |info| info.data.free.into()))
	}
}
