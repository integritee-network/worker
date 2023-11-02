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

#[cfg(all(not(feature = "std"), feature = "sgx"))]

#[cfg(feature = "sgx")]
use sgx_tstd as std;

use codec::{Decode, Encode};
use sp_runtime::{generic::Header as HeaderG, traits::BlakeTwo256, MultiAddress, MultiSignature};
use sp_std::vec::Vec;

use itp_utils::stringify::account_id_to_string;

use substrate_api_client::ac_node_api::StaticEvent;

pub type StorageProof = Vec<Vec<u8>>;

// Basic Types.
pub type Index = u32;
pub type Balance = u128;
pub type Hash = sp_core::H256;

// Account Types.
pub type AccountId = sp_core::crypto::AccountId32;
pub type AccountData = pallet_balances::AccountData<Balance>;
pub type AccountInfo = frame_system::AccountInfo<Index, AccountData>;
pub type Address = MultiAddress<AccountId, ()>;
// todo! make generic
/// The type used to represent the kinds of proxying allowed.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, Debug)]
pub enum ProxyType {
	Any,
	NonTransfer,
	Governance,
	Staking,
}

// Block Types
pub type BlockNumber = u32;
pub type Header = HeaderG<BlockNumber, BlakeTwo256>;
pub type BlockHash = sp_core::H256;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

#[derive(Encode, Decode, Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParentchainId {
	/// The Integritee Parentchain, the trust root of the enclave and serving finality to sidechains.
	Integritee,
	/// A target chain containing custom business logic.
	TargetA,
	/// Another target chain containing custom business logic.
	TargetB,
}

pub trait IdentifyParentchain {
	fn parentchain_id(&self) -> ParentchainId;
}

pub trait FilterEvents {
	type Error: From<ParentchainError>;
	fn get_extrinsic_statuses(&self) -> core::result::Result<Vec<ExtrinsicStatus>, Self::Error>;

	fn get_transfer_events(&self) -> core::result::Result<Vec<BalanceTransfer>, Self::Error>;
}

#[derive(Encode, Decode, Debug)]
pub struct ExtrinsicSuccess;

impl StaticEvent for ExtrinsicSuccess {
	const PALLET: &'static str = "System";
	const EVENT: &'static str = "ExtrinsicSuccess";
}

#[derive(Encode, Decode)]
pub struct ExtrinsicFailed;

impl StaticEvent for ExtrinsicFailed {
	const PALLET: &'static str = "System";
	const EVENT: &'static str = "ExtrinsicFailed";
}

#[derive(Debug)]
pub enum ExtrinsicStatus {
	Success,
	Failed,
}

#[derive(Encode, Decode, Debug)]
pub struct BalanceTransfer {
	pub from: AccountId,
	pub to: AccountId,
	pub amount: Balance,
}

impl core::fmt::Display for BalanceTransfer {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let message = format!(
			"BalanceTransfer :: from: {}, to: {}, amount: {}",
			account_id_to_string::<AccountId>(&self.from),
			account_id_to_string::<AccountId>(&self.to),
			self.amount
		);
		write!(f, "{}", message)
	}
}

impl StaticEvent for BalanceTransfer {
	const PALLET: &'static str = "Balances";
	const EVENT: &'static str = "Transfer";
}

pub trait HandleParentchainEvents {
	const SHIELDING_ACCOUNT: AccountId;
	fn handle_events(events: impl FilterEvents) -> core::result::Result<(), ParentchainError>;
	fn shield_funds(account: &AccountId, amount: Balance) -> core::result::Result<(), ParentchainError>;
}

#[derive(Debug)]
pub enum ParentchainError {
	ShieldFundsFailure,
}

impl core::fmt::Display for ParentchainError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let mut message: &str = "";
		match &self {
			ParentchainError::ShieldFundsFailure => {
				message = "Parentchain Error: ShieldFundsFailure";
			}
		}
		write!(f, "{}", message)
	}
}

impl From<ParentchainError> for () {
	fn from(_: ParentchainError) -> Self {}
}
