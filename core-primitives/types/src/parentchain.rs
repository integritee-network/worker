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

//! Parentchain specific params. Be sure to change them if your node uses different types.

use codec::{Decode, Encode};
use sp_runtime::{generic::Header as HeaderG, traits::BlakeTwo256, MultiAddress, MultiSignature};
use sp_std::vec::Vec;

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
	fn get_extrinsic_statuses(&self) -> Result<Vec<ExtrinsicStatus>>;

	fn get_transfer_events(&self) -> Result<Vec<BalanceTransfer>>;
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

impl StaticEvent for BalanceTransfer {
	const PALLET: &'static str = "Balances";
	const EVENT: &'static str = "Transfer";
}

pub struct ParentchainEventHandler;

pub trait HandleParentchainEvents {
	const SHIELDING_ACCOUNT: AccountId;
	fn shield_funds(account: &AccountId, amount: Balance) -> Result<(), ParentchainError>;
}

pub enum ParentchainError {
	ShieldFundsFailure,
}
