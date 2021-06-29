use sp_core::crypto::Pair;
use substrate_api_client::Api;
use sp_runtime::MultiSignature;

use substratee_node_primitives::AccountId;

use crate::ApiResult;

/// ApiClient extension that contains some convenience methods around accounts.
pub trait AccountApi {
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32>;
	fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128>;
}

impl<P: Pair> AccountApi for Api<P>
	where
		MultiSignature: From<P::Signature>
{
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32> {
		Ok(self.get_account_info(who)?
			.map_or_else(|| 0, |info| info.nonce))
	}

	fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128> {
		Ok(self.get_account_data(who)?
			.map_or_else(|| 0, |data| data.free))
	}
}
