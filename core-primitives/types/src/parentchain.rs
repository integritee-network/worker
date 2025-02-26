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

use crate::{xcm::Location, OpaqueCall, PalletString, ShardIdentifier};
use alloc::{format, vec::Vec};
use codec::{Decode, Encode};
use core::fmt::Debug;
use frame_support::pallet_prelude::Pays;
use itp_stf_primitives::traits::{IndirectExecutor, TrustedCallVerification};
use itp_utils::stringify::account_id_to_string;
use pallet_assets::ExistenceReason;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
pub use sidechain_primitives::SidechainBlockConfirmation;
use sp_core::bounded::alloc;
use sp_runtime::{
	generic::{Era, Header as HeaderG},
	traits::BlakeTwo256,
	DispatchError, MultiAddress, MultiSignature,
};
use substrate_api_client::{
	ac_node_api::StaticEvent,
	ac_primitives::{DispatchClass, Weight},
};
use teeracle_primitives::ExchangeRate;
use teerex_primitives::{SgxAttestationMethod, SgxStatus};

pub type StorageProof = Vec<Vec<u8>>;

// Basic Types.
pub type Index = u32;
pub type Balance = u128;
pub type Hash = sp_core::H256;
pub type ParentchainAssetIdNative = u32;

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

// the upstream type has private fields, so we re-define it
#[derive(Clone, Encode, Debug, Decode, Eq, PartialEq)]
pub struct AssetAccount {
	/// The balance.
	pub balance: Balance,
	/// Whether the account is frozen.
	pub is_frozen: bool,
	/// The reason for the existence of the account.
	pub reason: ExistenceReason<Balance>,
	/// Additional "sidecar" data, in case some other pallet wants to use this storage item.
	pub extra: (),
}

impl Default for AssetAccount {
	fn default() -> Self {
		Self { balance: 0, is_frozen: false, reason: ExistenceReason::Consumer, extra: () }
	}
}

#[derive(Encode, Decode, Copy, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum ParentchainId {
	/// The Integritee Parentchain, the trust root of the enclave and serving finality to sidechains.
	#[default]
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
			ParentchainId::Integritee => "Integritee",
			ParentchainId::TargetA => "TargetA",
			ParentchainId::TargetB => "TargetB",
		};
		write!(f, "{}", message)
	}
}

#[cfg(feature = "std")]
impl std::str::FromStr for ParentchainId {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"integritee" => Ok(ParentchainId::Integritee),
			"target-a" => Ok(ParentchainId::TargetA),
			"target-b" => Ok(ParentchainId::TargetB),
			_ => Err("Invalid ParentchainId"),
		}
	}
}

pub trait IdentifyParentchain {
	fn parentchain_id(&self) -> ParentchainId;
	fn genesis_hash(&self) -> Option<Hash>;
}

pub trait FilterEvents {
	type Error: From<ParentchainError> + core::fmt::Debug;
	fn get_extrinsic_statuses(&self) -> core::result::Result<Vec<ExtrinsicStatus>, Self::Error>;

	fn get_events<Event: Default + StaticEvent>(
		&self,
	) -> core::result::Result<Vec<Event>, Self::Error>;
}

#[derive(Encode, Decode, Debug)]
pub struct ExtrinsicSuccess;

impl StaticEvent for ExtrinsicSuccess {
	const PALLET: &'static str = "System";
	const EVENT: &'static str = "ExtrinsicSuccess";
}

#[derive(Encode, Decode, Debug)]
pub struct DispatchEventInfo {
	/// Weight of this transaction.
	pub weight: Weight,
	/// Class of this transaction.
	pub class: DispatchClass,
	/// Does this transaction pay fees.
	pub pays_fee: Pays,
}
#[derive(Encode, Decode, Debug)]
pub struct ExtrinsicFailed {
	pub dispatch_error: DispatchError,
	pub dispatch_info: DispatchEventInfo,
}

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

impl Default for BalanceTransfer {
	fn default() -> Self {
		BalanceTransfer { from: [0u8; 32].into(), to: [0u8; 32].into(), amount: 0 }
	}
}

impl StaticEvent for BalanceTransfer {
	const PALLET: &'static str = "Balances";
	const EVENT: &'static str = "Transfer";
}

#[derive(Encode, Decode, Debug)]
pub struct ForeignAssetsTransferred {
	pub asset_id: Location,
	pub from: AccountId,
	pub to: AccountId,
	pub amount: Balance,
}

impl core::fmt::Display for ForeignAssetsTransferred {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = format!(
			"ForeignAssetsTransferred :: asset: {:?}, from: {}, to: {}, amount: {}",
			&self.asset_id,
			account_id_to_string::<AccountId>(&self.from),
			account_id_to_string::<AccountId>(&self.to),
			self.amount
		);
		write!(f, "{}", message)
	}
}

impl Default for ForeignAssetsTransferred {
	fn default() -> Self {
		ForeignAssetsTransferred {
			asset_id: Default::default(),
			from: [0u8; 32].into(),
			to: [0u8; 32].into(),
			amount: 0,
		}
	}
}
impl StaticEvent for ForeignAssetsTransferred {
	const PALLET: &'static str = "ForeignAssets";
	const EVENT: &'static str = "Transferred";
}

#[derive(Encode, Decode, Debug)]
pub struct NativeAssetsTransferred {
	pub asset_id: u32,
	pub from: AccountId,
	pub to: AccountId,
	pub amount: Balance,
}

impl core::fmt::Display for NativeAssetsTransferred {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = format!(
			"NativeAssetsTransferred :: asset: {:?}, from: {}, to: {}, amount: {}",
			&self.asset_id,
			account_id_to_string::<AccountId>(&self.from),
			account_id_to_string::<AccountId>(&self.to),
			self.amount
		);
		write!(f, "{}", message)
	}
}

impl Default for NativeAssetsTransferred {
	fn default() -> Self {
		NativeAssetsTransferred {
			asset_id: Default::default(),
			from: [0u8; 32].into(),
			to: [0u8; 32].into(),
			amount: 0,
		}
	}
}
impl StaticEvent for NativeAssetsTransferred {
	const PALLET: &'static str = "Assets";
	const EVENT: &'static str = "Transferred";
}

#[derive(Encode, Decode, Debug)]
pub struct AddedSgxEnclave {
	pub registered_by: AccountId,
	pub worker_url: Option<PalletString>,
	pub tcb_status: Option<SgxStatus>,
	pub attestation_method: SgxAttestationMethod,
}

impl core::fmt::Display for AddedSgxEnclave {
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

impl StaticEvent for ProcessedParentchainBlock {
	const PALLET: &'static str = "EnclaveBridge";
	const EVENT: &'static str = "ProcessedParentchainBlock";
}

#[derive(Encode, Decode, Debug)]
pub struct ProcessedParentchainBlock {
	pub shard: ShardIdentifier,
	pub block_hash: Hash,
	pub trusted_calls_merkle_root: Hash,
	pub block_number: BlockNumber,
}

impl core::fmt::Display for ProcessedParentchainBlock {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = format!(
			"ProcessedParentchainBlock :: nr {} shard: {}, merkle: {:?}, block hash {:?}",
			self.block_number, self.shard, self.trusted_calls_merkle_root, self.block_hash
		);
		write!(f, "{}", message)
	}
}

impl StaticEvent for AddedSgxEnclave {
	const PALLET: &'static str = "EnclaveBridge";
	const EVENT: &'static str = "ProcessedParentchainBlock";
}

#[derive(Encode, Decode, Debug)]
pub struct OracleUpdated {
	pub oracle_data_name: PalletString,
	pub data_source: PalletString,
}

impl core::fmt::Display for OracleUpdated {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = format!(
			"OracleUpdated :: data name {:?} source: {:?}",
			self.oracle_data_name, self.data_source,
		);
		write!(f, "{}", message)
	}
}

impl StaticEvent for OracleUpdated {
	const PALLET: &'static str = "Teeracle";
	const EVENT: &'static str = "OracleUpdated";
}

#[derive(Encode, Decode, Debug)]
pub struct ExchangeRateUpdated {
	pub data_source: PalletString,
	pub trading_pair: PalletString,
	pub exchange_rate: ExchangeRate,
}

impl core::fmt::Display for ExchangeRateUpdated {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = format!(
			"OracleUpdated :: source {:?} trading pair: {:?}",
			self.data_source, self.trading_pair,
		);
		write!(f, "{}", message)
	}
}

impl StaticEvent for ExchangeRateUpdated {
	const PALLET: &'static str = "Teeracle";
	const EVENT: &'static str = "ExchangeRateUpdated";
}

#[derive(Encode, Decode, Debug, Default)]
pub struct ShardConfigUpdated(ShardIdentifier);

impl core::fmt::Display for ShardConfigUpdated {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let message = format!("ShardConfigUpdated :: shard {:?}", self.0,);
		write!(f, "{}", message)
	}
}

impl StaticEvent for ShardConfigUpdated {
	const PALLET: &'static str = "EnclaveBridge";
	const EVENT: &'static str = "ShardConfigUpdated";
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
		genesis_hash: Hash,
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

// All info for additionalParam except tip whi
#[derive(Encode, Debug, Clone, PartialEq, Eq)]
pub struct GenericMortality {
	pub era: Era,
	pub mortality_checkpoint: Option<Hash>,
}

impl GenericMortality {
	pub fn immortal() -> Self {
		Self { era: Era::Immortal, mortality_checkpoint: None }
	}
}

/// a wrapper to target calls to specific parentchains
#[derive(Encode, Debug, Clone, PartialEq, Eq)]
pub enum ParentchainCall {
	Integritee { call: OpaqueCall, mortality: GenericMortality },
	TargetA { call: OpaqueCall, mortality: GenericMortality },
	TargetB { call: OpaqueCall, mortality: GenericMortality },
}

impl ParentchainCall {
	pub fn as_integritee(&self) -> Option<(OpaqueCall, GenericMortality)> {
		if let Self::Integritee { call, mortality } = self {
			Some((call.clone(), mortality.clone()))
		} else {
			None
		}
	}
	pub fn as_target_a(&self) -> Option<(OpaqueCall, GenericMortality)> {
		if let Self::TargetA { call, mortality } = self {
			Some((call.clone(), mortality.clone()))
		} else {
			None
		}
	}
	pub fn as_target_b(&self) -> Option<(OpaqueCall, GenericMortality)> {
		if let Self::TargetB { call, mortality } = self {
			Some((call.clone(), mortality.clone()))
		} else {
			None
		}
	}
	pub fn as_opaque_call_for(&self, parentchain_id: ParentchainId) -> Option<OpaqueCall> {
		match parentchain_id {
			ParentchainId::Integritee =>
				if let Self::Integritee { call, mortality: _ } = self {
					Some(call.clone())
				} else {
					None
				},
			ParentchainId::TargetA =>
				if let Self::TargetA { call, mortality: _ } = self {
					Some(call.clone())
				} else {
					None
				},
			ParentchainId::TargetB =>
				if let Self::TargetB { call, mortality: _ } = self {
					Some(call.clone())
				} else {
					None
				},
		}
	}
}
