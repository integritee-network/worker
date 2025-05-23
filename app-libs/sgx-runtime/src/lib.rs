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

//! The Substrate Node Template sgx-runtime for SGX.
//! This is only meant to be used inside an SGX enclave with `#[no_std]`
//!
//! you should assemble your sgx-runtime to be used with your STF here
//! and get all your needed pallets in

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(prelude_import)]
#![feature(structural_match)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

#[cfg(feature = "evm")]
mod evm;

#[cfg(feature = "evm")]
pub use evm::{
	AddressMapping, EnsureAddressTruncated, EvmCall, FeeCalculator, FixedGasPrice,
	FixedGasWeightMapping, GasWeightMapping, HashedAddressMapping, IntoAddressMapping,
	SubstrateBlockHashMapping, GAS_PER_SECOND, MAXIMUM_BLOCK_WEIGHT, WEIGHT_PER_GAS,
};

use core::convert::{TryFrom, TryInto};
use frame_support::{ord_parameter_types, traits::ConstU32, weights::ConstantMultiplier};
use pallet_transaction_payment::CurrencyAdapter;
use sp_api::impl_runtime_apis;
use sp_core::OpaqueMetadata;
use sp_runtime::{
	create_runtime_str, generic,
	traits::{AccountIdLookup, BlakeTwo256, Block as BlockT},
};
use sp_std::prelude::*;
use sp_version::RuntimeVersion;

// Re-exports from itp-sgx-runtime-primitives.
pub use itp_sgx_runtime_primitives::{
	constants::SLOT_DURATION,
	types::{
		AccountData, AccountId, Address, Balance, BlockNumber, Hash, Header, Index, Signature,
	},
};

// A few exports that help ease life for downstream crates.
pub use frame_support::{
	construct_runtime, parameter_types,
	traits::{KeyOwnerProofSystem, Randomness},
	weights::{
		constants::{
			BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND,
		},
		IdentityFee, Weight,
	},
	StorageValue,
};
use frame_support::{
	traits::{ConstU128, ConstU8, EitherOfDiverse, EnsureOriginWithArg},
	PalletId,
};
use frame_system::{EnsureRoot, EnsureSignedBy};
use ita_assets_map::AssetId;
use itp_randomness::SgxRandomness;
use itp_sgx_runtime_primitives::types::Moment;
pub use pallet_assets::Call as AssetsCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_guess_the_number::{Call as GuessTheNumberCall, GuessType};
pub use pallet_notes::Call as NotesCall;
pub use pallet_parentchain::Call as ParentchainPalletCall;
pub use pallet_session_proxy::{
	Call as SessionProxyCall, SessionProxyCredentials, SessionProxyRole,
};
pub use pallet_shard_management::{Call as ShardManagementCall, ShardMode};
pub use pallet_timestamp::Call as TimestampCall;
use sp_core::crypto::AccountId32;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;
pub use sp_runtime::{Perbill, Permill};

/// Block type as expected by this sgx-runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// BlockId type as expected by this sgx-runtime.
pub type BlockId = generic::BlockId<Block>;

/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);
/// Unchecked extrinsic type as expected by this sgx-runtime.
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
>;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the sgx-runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
	use sp_runtime::generic;
	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	/// Opaque block header type.
	pub type Header = itp_sgx_runtime_primitives::types::Header;
	/// Opaque block type.
	pub type Block = super::Block;
	/// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;
}

pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("node-template"),
	impl_name: create_runtime_str!("node-template"),
	authoring_version: 1,
	spec_version: 1,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	state_version: 0,
};

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
	pub const Version: RuntimeVersion = VERSION;
	pub const BlockHashCount: BlockNumber = 2400;
	/// We allow for 2 seconds of compute with a 6 second average block time.
	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
		::with_sensible_defaults(Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND, u64::MAX), NORMAL_DISPATCH_RATIO);
	pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
		::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
	pub const SS58Prefix: u8 = 42;
}

// Configure FRAME pallets to include in sgx-runtime.

impl frame_system::Config for Runtime {
	/// The basic call filter to use in dispatchable.
	type BaseCallFilter = frame_support::traits::Everything;
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = BlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = BlockLength;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The aggregated dispatch type that is available for extrinsics.
	type RuntimeCall = RuntimeCall;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = AccountIdLookup<AccountId, ()>;
	/// The index type for storing how many extrinsics an account has signed.
	type Index = Index;
	/// The index type for blocks.
	type BlockNumber = BlockNumber;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The header type.
	type Header = Header;
	/// The ubiquitous event type.
	type RuntimeEvent = RuntimeEvent;
	/// The ubiquitous origin type.
	type RuntimeOrigin = RuntimeOrigin;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the sgx-runtime can invoke.
	type DbWeight = RocksDbWeight;
	/// Version of the sgx-runtime.
	type Version = Version;
	/// Converts a module to the index of the module in `construct_runtime!`.
	///
	/// This type is being generated by `construct_runtime!`.
	type PalletInfo = PalletInfo;
	/// What to do if a new account is created.
	type OnNewAccount = ();
	/// What to do if an account is fully reaped from the system.
	type OnKilledAccount = ();
	/// The data to be stored in an account.
	type AccountData = AccountData;
	/// Weight information for the extrinsics of this pallet.
	type SystemWeightInfo = ();
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	/// The set code logic, just the default since we're not a parachain.
	type OnSetCode = ();
	/// The maximum number of consumers allowed on a single account.
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
	/// A timestamp: milliseconds since the unix epoch.
	type Moment = Moment;
	type OnTimestampSet = GuessTheNumber;
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = ();
}

parameter_types! {
	pub const ExistentialDeposit: u128 = 500;
	pub const MaxLocks: u32 = 50;
}

impl pallet_balances::Config for Runtime {
	type MaxLocks = MaxLocks;
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	/// The type for recording an account's balance.
	type Balance = Balance;
	/// The ubiquitous event type.
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
	type HoldIdentifier = ();
	type FreezeIdentifier = ();
	type MaxHolds = ConstU32<0>;
	type MaxFreezes = ConstU32<0>;
}

parameter_types! {
	pub const TransactionByteFee: Balance = 1;
	pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = CurrencyAdapter<Balances, ()>;
	type OperationalFeeMultiplier = OperationalFeeMultiplier;
	type WeightToFee = IdentityFee<Balance>;
	type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
	type FeeMultiplierUpdate = ();
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
}

pub type ParentchainInstanceIntegritee = pallet_parentchain::Instance1;
impl pallet_parentchain::Config<ParentchainInstanceIntegritee> for Runtime {
	type WeightInfo = ();
	type RuntimeEvent = RuntimeEvent;
	type Moment = Moment;
}

pub type ParentchainInstanceTargetA = pallet_parentchain::Instance2;
impl pallet_parentchain::Config<crate::ParentchainInstanceTargetA> for Runtime {
	type WeightInfo = ();
	type RuntimeEvent = RuntimeEvent;
	type Moment = Moment;
}

pub type ParentchainInstanceTargetB = pallet_parentchain::Instance3;
impl pallet_parentchain::Config<crate::ParentchainInstanceTargetB> for Runtime {
	type WeightInfo = ();
	type RuntimeEvent = RuntimeEvent;
	type Moment = Moment;
}

impl pallet_shard_management::Config for Runtime {
	type WeightInfo = ();
	type Moment = Moment;
}

ord_parameter_types! {
	pub const GameMaster: AccountId32 = AccountId32::new([148, 117, 87, 242, 252, 96, 167, 29, 118, 69, 87, 119, 15, 57, 142, 82, 216, 8, 210, 102, 12, 213, 46, 76, 214, 5, 144, 153, 148, 113, 89, 95]);
}

parameter_types! {
	pub const MomentsPerDay: u64 = 86_400_000; // [ms/d]
	pub const RoundDuration: u64 = 7 * 86_400_000; // [ms/d]
	pub const GtnPalletId: PalletId = PalletId(*b"gsstnmbr");
}
impl pallet_guess_the_number::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type GameMaster =
		EitherOfDiverse<EnsureSignedBy<GameMaster, AccountId32>, EnsureRoot<AccountId32>>;
	type MomentsPerDay = MomentsPerDay;
	type WeightInfo = ();
	type RoundDuration = RoundDuration;
	type Randomness = SgxRandomness;
	type Currency = Balances;
	type PalletId = GtnPalletId;
	type MaxAttempts = ConstU8<10>;
	type MaxWinners = ConstU8<12>;
}

parameter_types! {
	pub const MaxNoteSize: u32 = 512;
	pub const MaxBucketSize: u32 = 51_200;
	pub const MaxTotalSize: u32 = 5_120_000;
}

impl pallet_notes::Config for Runtime {
	type MomentsPerDay = MomentsPerDay;
	type Currency = Balances;
	type MaxNoteSize = MaxNoteSize;
	type MaxBucketSize = MaxBucketSize;
	type MaxTotalSize = MaxTotalSize;
}

parameter_types! {
	pub const MaxProxiesPerOwner: u8 = 10;
}
impl pallet_session_proxy::Config for Runtime {
	type MomentsPerDay = MomentsPerDay;
	type Currency = Balances;
	type MaxProxiesPerOwner = MaxProxiesPerOwner;
}

/// always denies creation of assets
pub struct NoAssetCreators;

impl EnsureOriginWithArg<RuntimeOrigin, AssetId> for NoAssetCreators {
	type Success = AccountId;

	fn try_origin(
		o: RuntimeOrigin,
		_a: &AssetId,
	) -> sp_std::result::Result<Self::Success, RuntimeOrigin> {
		Err(o)
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn try_successful_origin(_a: &AssetIdForTrustBackedAssets) -> Result<RuntimeOrigin, ()> {
		Err(())
	}
}

impl pallet_assets::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Balance = Balance;
	type AssetId = AssetId;
	type AssetIdParameter = AssetId;
	type Currency = Balances;
	type CreateOrigin = NoAssetCreators;
	type ForceOrigin = EnsureRoot<AccountId>;
	type AssetDeposit = ConstU128<0>;
	type AssetAccountDeposit = ConstU128<0>;
	type MetadataDepositBase = ConstU128<0>;
	type MetadataDepositPerByte = ConstU128<0>;
	type ApprovalDeposit = ConstU128<0>;
	type StringLimit = ConstU32<50>;
	type Freezer = ();
	type WeightInfo = ();
	type CallbackHandle = ();
	type Extra = ();
	type RemoveItemsLimit = ConstU32<5>;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = ();
}

// The plain sgx-runtime without the `evm-pallet`
#[cfg(not(feature = "evm"))]
construct_runtime!(
	pub enum Runtime where
		Block = Block,
		NodeBlock = opaque::Block,
		UncheckedExtrinsic = UncheckedExtrinsic
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>} = 0,
		Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent} = 1,
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>} = 2,
		TransactionPayment: pallet_transaction_payment::{Pallet, Storage, Event<T>} = 3,
		Sudo: pallet_sudo::{Pallet, Call, Config<T>, Storage, Event<T>} = 4,
		ShardManagement: pallet_shard_management::{Pallet, Storage, Call} = 5,

		ParentchainIntegritee: pallet_parentchain::<Instance1>::{Pallet, Call, Event<T>} = 10,
		ParentchainTargetA: pallet_parentchain::<Instance2>::{Pallet, Call, Event<T>} = 11,
		ParentchainTargetB: pallet_parentchain::<Instance3>::{Pallet, Call, Event<T>} = 12,

		GuessTheNumber: pallet_guess_the_number::{Pallet, Call, Storage, Event<T>} = 30,

		Notes: pallet_notes::{Pallet, Call, Storage} = 40,
		SessionProxy: pallet_session_proxy::{Pallet, Call, Storage} = 41,

		Assets: pallet_assets::{Pallet, Call, Storage, Event<T>} = 50,
	}
);

// Runtime constructed with the evm pallet.
//
// We need add the compiler-flag for the whole macro because it does not support
// compiler flags withing the macro.
#[cfg(feature = "evm")]
construct_runtime!(
	pub enum Runtime where
		Block = Block,
		NodeBlock = opaque::Block,
		UncheckedExtrinsic = UncheckedExtrinsic
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>} = 0,
		Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent} = 1,
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>} = 2,
		TransactionPayment: pallet_transaction_payment::{Pallet, Storage, Event<T>} = 3,
		Sudo: pallet_sudo::{Pallet, Call, Config<T>, Storage, Event<T>} = 4,
		ShardManagement: pallet_shard_management::{Pallet, Storage, Call} = 5,

		ParentchainIntegritee: pallet_parentchain::<Instance1>::{Pallet, Call, Event<T>} = 10,
		ParentchainTargetA: pallet_parentchain::<Instance2>::{Pallet, Call, Event<T>} = 11,
		ParentchainTargetB: pallet_parentchain::<Instance3>::{Pallet, Call, Event<T>} = 12,

		Evm: pallet_evm::{Pallet, Call, Storage, Config, Event<T>} = 20,

		GuessTheNumber: pallet_guess_the_number::{Pallet, Call, Storage, Event<T>} = 30,

		Notes: pallet_notes::{Pallet, Call, Storage} = 40,
		SessionProxy: pallet_session_proxy::{Pallet, Call, Storage} = 41,

		Assets: pallet_assets::{Pallet, Call, Storage, Event<T>} = 50,
	}
);

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block);
		}

		fn initialize_block(header: &<Block as BlockT>::Header) {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> sp_std::vec::Vec<u32> {
			Runtime::metadata_versions()
		}
	}

}
