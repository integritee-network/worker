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
use itp_api_client_types::{
	traits::GetAccountInformation, Api, Config, ParentchainPlainTipRuntimeConfig, Request,
};
use itp_types::parentchain::{AccountData, Balance};

/// ApiClient extension that contains some convenience methods around accounts.
// Todo: make generic over `Config` type instead?
pub trait AccountApi {
	type AccountId;
	type Index;
	type Balance;

	fn get_nonce_of(&self, who: &Self::AccountId) -> ApiResult<Self::Index>;
	fn get_free_balance(&self, who: &Self::AccountId) -> ApiResult<Self::Balance>;
}

impl<RuntimeConfig, Client> AccountApi for Api<RuntimeConfig, Client>
where
	Client: Request,
	RuntimeConfig: Config<
		AccountData = substrate_api_client::ac_primitives::AccountData<Balance>,
		Balance = Balance,
	>,
{
	type AccountId = <RuntimeConfig as Config>::AccountId;
	type Index = <RuntimeConfig as Config>::Index;
	type Balance = <RuntimeConfig as Config>::Balance;

	fn get_nonce_of(&self, who: &Self::AccountId) -> ApiResult<Self::Index> {
		Ok(self.get_account_info(who)?.map(|info| info.nonce).unwrap_or_default())
	}

	fn get_free_balance(&self, who: &Self::AccountId) -> ApiResult<Self::Balance> {
		Ok(self.get_account_data(who)?.map(|data| data.free).unwrap_or_default())
	}
}
