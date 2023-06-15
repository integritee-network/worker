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

use crate::{helpers::ensure_enclave_signer_account, StfError, };
pub use ita_sgx_runtime::{Balance, Index};
use ita_sgx_runtime::{Runtime, System};
use sp_runtime::{traits::Verify, MultiAddress};
use itp_stf_primitives::types::{AccountId};
use frame_support::{ensure, traits::UnfilteredDispatchable};
use std::{format};

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

pub trait PrivacySidechainTrait {
    const SHIELDING_ACCOUNT: AccountId;
    fn shield_funds(account: AccountId, amount: Balance) -> Result<(), StfError>;
}

pub struct PrivacySidechain;

impl PrivacySidechainTrait for PrivacySidechain {
    const SHIELDING_ACCOUNT: AccountId = ALICE_ENCODED.into();
    fn shield_funds(account: AccountId, amount: Balance) -> Result<(), StfError> {
        let account_info = System::account(&account);
        ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
            who: MultiAddress::Id(account),
            new_free: account_info.data.free + amount,
            new_reserved: account_info.data.reserved,
        }
        .dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
        .map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?;

        Ok(())
    }
}





