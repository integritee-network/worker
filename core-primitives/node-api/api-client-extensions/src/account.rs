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
use itp_types::parentchain::{AccountData, AccountId, Balance, Index};
use substrate_api_client::{
	rpc::Request, Api, ExtrinsicParams, FrameSystemConfig, GetAccountInformation, SignExtrinsic,
};

/// ApiClient extension that contains some convenience methods around accounts.
pub trait AccountApi {
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<Index>;
	fn get_free_balance(&self, who: &AccountId) -> ApiResult<Balance>;
}

impl<Signer, Client, Params, Runtime> AccountApi for Api<Signer, Client, Params, Runtime>
where
	Signer: SignExtrinsic<Runtime::AccountId>,
	Client: Request,
	Runtime: FrameSystemConfig<AccountId = AccountId, AccountData = AccountData, Index = Index>,
	Params: ExtrinsicParams<Runtime::Index, Runtime::Hash>,
{
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<Index> {
		Ok(self.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce))
	}

	fn get_free_balance(&self, who: &AccountId) -> ApiResult<Balance> {
		Ok(self.get_account_data(who)?.map_or_else(|| 0, |data| data.free))
	}
}
