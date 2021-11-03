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

use crate::{helpers::get_account_info, StfError};
use itp_storage::storage_value_key;
use log_sgx::*;
use sgx_externalities::SgxExternalitiesTrait;
use sgx_runtime::{Balance, Runtime};
use sgx_tstd as std;
use sp_core::{crypto::AccountId32, ed25519, Pair};
use sp_io::SgxExternalities;
use sp_runtime::MultiAddress;
use std::{string::ToString, vec, vec::Vec};
use support::traits::UnfilteredDispatchable;

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

const TEST_SEED: Seed = *b"12345678901234567890123456789012";

const ALICE_FUNDS: Balance = 1000000000000000;

pub fn test_account() -> ed25519::Pair {
	ed25519::Pair::from_seed(&TEST_SEED)
}

pub fn test_genesis_setup(state: &mut SgxExternalities) {
	// set alice sudo account
	set_sudo_account(state, &ALICE_ENCODED);
	trace!("Set new sudo account: {:?}", &ALICE_ENCODED);

	let endowees: Vec<(AccountId32, Balance, Balance)> = vec![
		(test_account().public().into(), 2000, 2000),
		(ALICE_ENCODED.into(), ALICE_FUNDS, ALICE_FUNDS),
	];

	endow(state, endowees);
}

fn set_sudo_account(state: &mut SgxExternalities, account_encoded: &[u8]) {
	state.execute_with(|| {
		sp_io::storage::set(&storage_value_key("Sudo", "Key"), account_encoded);
	})
}

fn endow(
	state: &mut SgxExternalities,
	endowees: impl IntoIterator<Item = (AccountId32, Balance, Balance)>,
) {
	state.execute_with(|| {
		for e in endowees.into_iter() {
			let account = e.0;

			sgx_runtime::BalancesCall::<Runtime>::set_balance(
				MultiAddress::Id(account.clone()),
				e.1,
				e.2,
			)
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|_| StfError::Dispatch("balance_set_balance".to_string()))
			.unwrap();

			let print_public: [u8; 32] = account.clone().into();
			if let Some(info) = get_account_info(&print_public.into()) {
				debug!("{:?} balance is {}", print_public, info.data.free);
			} else {
				debug!("{:?} balance is zero", print_public);
			}
		}
	});
}
