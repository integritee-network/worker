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

use crate::{OpaqueCall, PalletString};
use alloc::{format, vec::Vec};
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_stf_primitives::traits::{IndirectExecutor, TrustedCallVerification};
use itp_utils::stringify::account_id_to_string;
use sp_core::bounded::alloc;
use sp_runtime::{generic::Header as HeaderG, traits::BlakeTwo256, MultiAddress, MultiSignature};
use substrate_api_client::ac_node_api::StaticEvent;
use teerex_primitives::{SgxAttestationMethod, SgxStatus};

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

#[cfg(feature = "std")]
impl std::fmt::Display for ParentchainId {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let message = match self {
			ParentchainId::Integritee => "L1:Integritee",
			ParentchainId::TargetA => "L1:AssetHub",
			ParentchainId::TargetB => "L1:UNDEFINED",
		};
		write!(f, "{}", message)
	}
}

pub trait IdentifyParentchain {
	fn parentchain_id(&self) -> ParentchainId;
}

pub trait FilterEvents {
	type Error: From<ParentchainError> + core::fmt::Debug;
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
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
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

#[derive(Encode, Decode, Debug)]
pub struct AddedSgxEnclave {
	pub registered_by: AccountId,
	pub worker_url: Option<PalletString>,
	pub tcb_status: Option<SgxStatus>,
	pub attestation_method: SgxAttestationMethod,
}

impl core::fmt::Display for crate::parentchain::AddedSgxEnclave {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = format!(
			"AddedSgxEnclave :: from: {}, url: {:?}, status: {:?}, method: {:?}",
			account_id_to_string::<AccountId>(&self.registered_by),
			self.worker_url,
			self.tcb_status,
			self.attestation_method
		);
		write!(f, "{}", message)
	}
}

impl StaticEvent for crate::parentchain::AddedSgxEnclave {
	const PALLET: &'static str = "Teerex";
	const EVENT: &'static str = "AddedSgxEnclave";
}

pub trait HandleParentchainEvents<Executor, TCS, Error>
where
	Executor: IndirectExecutor<TCS, Error>,
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
{
	fn handle_events(
		executor: &Executor,
		events: impl FilterEvents,
		vault_account: &AccountId,
	) -> core::result::Result<(), Error>;
}

#[derive(Debug)]
pub enum ParentchainError {
	ShieldFundsFailure,
	FunctionalityDisabled,
}

impl core::fmt::Display for ParentchainError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = match &self {
			ParentchainError::ShieldFundsFailure => "Parentchain Error: ShieldFundsFailure",
			ParentchainError::FunctionalityDisabled => "Parentchain Error: FunctionalityDisabled",
		};
		write!(f, "{}", message)
	}
}

impl From<ParentchainError> for () {
	fn from(_: ParentchainError) -> Self {}
}

/// a wrapper to target calls to specific parentchains
#[derive(Encode, Debug, Clone, PartialEq, Eq)]
pub enum ParentchainCall {
	Integritee(OpaqueCall),
	TargetA(OpaqueCall),
	TargetB(OpaqueCall),
}

impl ParentchainCall {
	pub fn as_integritee(&self) -> Option<OpaqueCall> {
		if let Self::Integritee(call) = self {
			Some(call.clone())
		} else {
			None
		}
	}
	pub fn as_target_a(&self) -> Option<OpaqueCall> {
		if let Self::TargetA(call) = self {
			Some(call.clone())
		} else {
			None
		}
	}
	pub fn as_target_b(&self) -> Option<OpaqueCall> {
		if let Self::TargetB(call) = self {
			Some(call.clone())
		} else {
			None
		}
	}
	pub fn as_opaque_call_for(&self, parentchain_id: ParentchainId) -> Option<OpaqueCall> {
		match parentchain_id {
			ParentchainId::Integritee =>
				if let Self::Integritee(call) = self {
					Some(call.clone())
				} else {
					None
				},
			ParentchainId::TargetA =>
				if let Self::TargetA(call) = self {
					Some(call.clone())
				} else {
					None
				},
			ParentchainId::TargetB =>
				if let Self::TargetB(call) = self {
					Some(call.clone())
				} else {
					None
				},
		}
	}
}
