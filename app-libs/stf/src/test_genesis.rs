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
use frame_support::traits::UnfilteredDispatchable;
use ita_sgx_runtime::{Balance, Runtime, System};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_primitives::error::StfError;
use itp_storage::storage_value_key;
use log::*;
use sgx_tstd as std;
use sp_core::{crypto::AccountId32, ed25519, Pair};
use sp_runtime::MultiAddress;
use std::{format, vec, vec::Vec};

#[cfg(feature = "evm")]
use crate::evm_helpers::get_evm_account;
#[cfg(feature = "evm")]
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping};
use itp_utils::stringify::account_id_to_string;

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

const ENDOWED_SEED: Seed = *b"12345678901234567890123456789012";
const SECOND_ENDOWED_SEED: Seed = *b"22345678901234567890123456789012";
const UNENDOWED_SEED: Seed = *b"92345678901234567890123456789012";

const ALICE_FUNDS: Balance = 10_000_000_000_000_000;
pub const ENDOWED_ACC_FUNDS: Balance = 2_000_000_000_000;
pub const SECOND_ENDOWED_ACC_FUNDS: Balance = 1_000_000_000_000;

pub fn endowed_account() -> ed25519::Pair {
	ed25519::Pair::from_seed(&ENDOWED_SEED)
}
pub fn second_endowed_account() -> ed25519::Pair {
	ed25519::Pair::from_seed(&SECOND_ENDOWED_SEED)
}

pub fn unendowed_account() -> ed25519::Pair {
	ed25519::Pair::from_seed(&UNENDOWED_SEED)
}

pub fn test_genesis_setup(state: &mut impl SgxExternalitiesTrait) {
	// set alice sudo account
	set_sudo_account(state, &ALICE_ENCODED);
	trace!("Set new sudo account: {:?}", &ALICE_ENCODED);

	let mut endowees = test_genesis_endowees();

	append_funded_alice_evm_account(&mut endowees);

	endow(state, endowees);
}

pub fn test_genesis_endowees() -> Vec<(AccountId32, Balance)> {
	vec![
		(endowed_account().public().into(), ENDOWED_ACC_FUNDS),
		(second_endowed_account().public().into(), SECOND_ENDOWED_ACC_FUNDS),
		(ALICE_ENCODED.into(), ALICE_FUNDS),
	]
}
#[cfg(feature = "evm")]
fn append_funded_alice_evm_account(endowees: &mut Vec<(AccountId32, Balance)>) {
	let alice_evm = get_evm_account(&ALICE_ENCODED.into());
	let alice_evm_substrate_version = HashedAddressMapping::into_account_id(alice_evm);
	let mut other: Vec<(AccountId32, Balance)> = vec![(alice_evm_substrate_version, ALICE_FUNDS)];
	endowees.append(other.as_mut());
}

#[cfg(not(feature = "evm"))]
fn append_funded_alice_evm_account(_: &mut Vec<(AccountId32, Balance)>) {}

fn set_sudo_account(state: &mut impl SgxExternalitiesTrait, account_encoded: &[u8]) {
	state.execute_with(|| {
		sp_io::storage::set(&storage_value_key("Sudo", "Key"), account_encoded);
	})
}

pub fn endow(
	state: &mut impl SgxExternalitiesTrait,
	endowees: impl IntoIterator<Item = (AccountId32, Balance)>,
) {
	state.execute_with(|| {
		for e in endowees.into_iter() {
			let account = e.0;

			ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
				who: MultiAddress::Id(account.clone()),
				new_free: e.1,
			}
			.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
			.map_err(|e| StfError::Dispatch(format!("Balance Set Balance error: {:?}", e.error)))
			.unwrap();

			let account_info = System::account(&account);
			info!(
				"endowed {}. balance is {}",
				account_id_to_string(&account),
				account_info.data.free
			);
		}
	});
}
