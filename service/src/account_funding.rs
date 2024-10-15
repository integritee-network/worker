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

use crate::error::{Error, ServiceResult};
use codec::Encode;
use itp_node_api::api_client::{AccountApi, ParentchainApi, TEEREX};
use itp_settings::worker::REGISTERING_FEE_FACTOR_FOR_INIT_FUNDS;
use itp_types::{
	parentchain::{AccountId, Balance, ParentchainId},
	Moment,
};
use log::*;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	Pair,
};
use sp_keyring::AccountKeyring;
use sp_runtime::{MultiAddress, Saturating};
use std::{fmt::Display, thread, time::Duration};
use substrate_api_client::{
	ac_compose_macros::compose_extrinsic, ac_primitives::Bytes, extrinsic::BalancesExtrinsics,
	GetBalance, GetStorage, GetTransactionPayment, SubmitAndWatch, SystemApi, XtStatus,
};
use teerex_primitives::SgxAttestationMethod;

const SGX_RA_PROOF_MAX_LEN: usize = 5000;
const MAX_URL_LEN: usize = 256;

#[derive(Clone)]
pub enum AccountAndRole {
	EnclaveSigner(AccountId),
	ShardVault(AccountId),
}

impl Display for AccountAndRole {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AccountAndRole::EnclaveSigner(account_id) => {
				write!(f, "EnclaveSigner({})", account_id.to_ss58check())
			},
			AccountAndRole::ShardVault(account_id) => {
				write!(f, "ShardVault({})", account_id.to_ss58check())
			},
		}
	}
}

impl AccountAndRole {
	pub fn account_id(&self) -> AccountId {
		match self {
			AccountAndRole::EnclaveSigner(account_id) => account_id.clone(),
			AccountAndRole::ShardVault(account_id) => account_id.clone(),
		}
	}
}

/// Information about an account on a specified parentchain.
pub trait ParentchainAccountInfo {
	fn free_balance(&self) -> ServiceResult<Balance>;
	fn parentchain_id(&self) -> ServiceResult<ParentchainId>;
	fn account_and_role(&self) -> ServiceResult<AccountAndRole>;
	fn decimals(&self) -> ServiceResult<u64>;
}

pub struct ParentchainAccountInfoProvider {
	parentchain_id: ParentchainId,
	node_api: ParentchainApi,
	account_and_role: AccountAndRole,
}

impl ParentchainAccountInfo for ParentchainAccountInfoProvider {
	fn free_balance(&self) -> ServiceResult<Balance> {
		self.node_api
			.get_free_balance(&self.account_and_role.account_id())
			.map_err(|e| e.into())
	}

	fn parentchain_id(&self) -> ServiceResult<ParentchainId> {
		Ok(self.parentchain_id)
	}

	fn account_and_role(&self) -> ServiceResult<AccountAndRole> {
		Ok(self.account_and_role.clone())
	}

	fn decimals(&self) -> ServiceResult<u64> {
		let properties = self.node_api.get_system_properties()?;
		properties
			.get("tokenDecimals")
			.ok_or(Error::MissingDecimals)?
			.as_u64()
			.ok_or(Error::ConversionError)
	}
}

impl ParentchainAccountInfoProvider {
	pub fn new(
		parentchain_id: ParentchainId,
		node_api: ParentchainApi,
		account_and_role: AccountAndRole,
	) -> Self {
		ParentchainAccountInfoProvider { parentchain_id, node_api, account_and_role }
	}
}

/// evaluate if the enclave should have more funds and how much more
/// in --dev mode: let Alice pay for missing funds
/// in production mode: wait for manual transfer before continuing
pub fn setup_reasonable_account_funding(
	api: &ParentchainApi,
	accountid: &AccountId32,
	parentchain_id: ParentchainId,
	is_development_mode: bool,
) -> ServiceResult<()> {
	loop {
		let needed = estimate_funds_needed_to_run_for_a_while(api, accountid, parentchain_id)?;
		let free = api.get_free_balance(accountid)?;
		let missing_funds = needed.saturating_sub(free);

		if missing_funds < needed * 2 / 3 {
			return Ok(())
		}

		if is_development_mode {
			info!("[{:?}] Alice will grant {:?} to {:?}", parentchain_id, missing_funds, accountid);
			bootstrap_funds_from_alice(api, accountid, missing_funds)?;
		} else {
			error!(
				"[{:?}] Enclave account needs funding. please send at least {:?} to {:?}",
				parentchain_id, missing_funds, accountid
			);
			thread::sleep(Duration::from_secs(10));
		}
	}
}

fn estimate_funds_needed_to_run_for_a_while(
	api: &ParentchainApi,
	accountid: &AccountId32,
	parentchain_id: ParentchainId,
) -> ServiceResult<Balance> {
	let existential_deposit = api.get_existential_deposit()?;
	info!("[{:?}] Existential deposit is = {:?}", parentchain_id, existential_deposit);

	let mut min_required_funds: Balance = existential_deposit;
	min_required_funds += shard_vault_initial_funds(api)?;

	let transfer_fee = estimate_transfer_fee(api)?;
	info!("[{:?}] a single transfer costs {:?}", parentchain_id, transfer_fee);
	min_required_funds += 1000 * transfer_fee;

	// Check if this is an integritee chain and Compose a register_sgx_enclave extrinsic
	if let Ok(ra_renewal) = api.get_constant::<Moment>("Teerex", "MaxAttestationRenewalPeriod") {
		info!("[{:?}] this chain has the teerex pallet. estimating RA fees", parentchain_id);
		let encoded_xt: Bytes = compose_extrinsic!(
			api,
			TEEREX,
			"register_sgx_enclave",
			vec![0u8; SGX_RA_PROOF_MAX_LEN],
			Some(vec![0u8; MAX_URL_LEN]),
			SgxAttestationMethod::Dcap { proxied: false }
		)
		.encode()
		.into();
		let tx_fee =
			api.get_fee_details(&encoded_xt, None).unwrap().unwrap().inclusion_fee.unwrap();
		let ra_fee = tx_fee.base_fee + tx_fee.len_fee + tx_fee.adjusted_weight_fee;
		info!(
			"[{:?}] one enclave registration costs {:?} and needs to be renewed every {:?}h",
			parentchain_id,
			ra_fee,
			ra_renewal / 1_000 / 3_600
		);
		min_required_funds += 5 * ra_fee;
	} else {
		info!("[{:?}] this chain has no teerex pallet, no need to add RA fees", parentchain_id);
	}

	info!(
		"[{:?}] we estimate the funding requirement for the primary validateer (worst case) to be {:?}",
		parentchain_id,
		min_required_funds
	);
	Ok(min_required_funds)
}

pub fn estimate_fee(api: &ParentchainApi, encoded_extrinsic: Vec<u8>) -> Result<u128, Error> {
	let reg_fee_details = api.get_fee_details(&encoded_extrinsic.into(), None)?;
	match reg_fee_details {
		Some(details) => match details.inclusion_fee {
			Some(fee) => Ok(fee.inclusion_fee()),
			None => Err(Error::Custom(
				"Inclusion fee for the registration of the enclave is None!".into(),
			)),
		},
		None =>
			Err(Error::Custom("Fee Details for the registration of the enclave is None !".into())),
	}
}

/// Alice sends some funds to the account. only for dev chains testing
fn bootstrap_funds_from_alice(
	api: &ParentchainApi,
	accountid: &AccountId32,
	funding_amount: u128,
) -> Result<(), Error> {
	let alice = AccountKeyring::Alice.pair();
	let alice_acc = AccountId32::from(*alice.public().as_array_ref());

	let alice_free = api.get_free_balance(&alice_acc)?;
	trace!("    Alice's free balance = {:?}", alice_free);
	let nonce = api.get_nonce_of(&alice_acc)?;
	trace!("    Alice's Account Nonce is {}", nonce);

	if funding_amount > alice_free {
		println!(
            "funding amount is too high: please change EXISTENTIAL_DEPOSIT_FACTOR_FOR_INIT_FUNDS ({:?})",
            funding_amount
        );
		return Err(Error::ApplicationSetup)
	}

	let mut alice_signer_api = api.clone();
	alice_signer_api.set_signer(alice.into());

	println!("[+] send extrinsic: bootstrap funding Enclave from Alice's funds");
	let xt = alice_signer_api
		.balance_transfer_allow_death(MultiAddress::Id(accountid.clone()), funding_amount);
	let xt_report = alice_signer_api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock)?;
	info!(
		"[<] L1 extrinsic success. extrinsic hash: {:?} / status: {:?}",
		xt_report.extrinsic_hash, xt_report.status
	);
	// Verify funds have arrived.
	let free_balance = alice_signer_api.get_free_balance(accountid);
	trace!("TEE's NEW free balance = {:?}", free_balance);

	Ok(())
}

/// precise estimation of necessary funds to register a hardcoded number of proxies
pub fn shard_vault_initial_funds(api: &ParentchainApi) -> Result<Balance, Error> {
	let proxy_deposit_base: Balance = api.get_constant("Proxy", "ProxyDepositBase")?;
	let proxy_deposit_factor: Balance = api.get_constant("Proxy", "ProxyDepositFactor")?;
	let transfer_fee = estimate_transfer_fee(api)?;
	let existential_deposit = api.get_existential_deposit()?;
	info!("Proxy Deposit is {:?} base + {:?} per proxy", proxy_deposit_base, proxy_deposit_factor);
	Ok(proxy_deposit_base + 10 * proxy_deposit_factor + 500 * transfer_fee + existential_deposit)
}

/// precise estimation of a single transfer fee
pub fn estimate_transfer_fee(api: &ParentchainApi) -> Result<Balance, Error> {
	let encoded_xt: Bytes = api
		.balance_transfer_allow_death(AccountId::from([0u8; 32]).into(), 1000000000000)
		.encode()
		.into();
	let tx_fee = api.get_fee_details(&encoded_xt, None).unwrap().unwrap().inclusion_fee.unwrap();
	let transfer_fee = tx_fee.base_fee + tx_fee.len_fee + tx_fee.adjusted_weight_fee;
	Ok(transfer_fee)
}
