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

//! Common settings for the worker and the enclave. It is strictly `no_std`

#![no_std]

#[cfg(any(
	all(feature = "sidechain", feature = "offchain-worker"),
	all(feature = "sidechain", feature = "teeracle"),
	all(feature = "teeracle", feature = "offchain-worker")
))]
compile_error!(
	"feature \"sidechain\" , \"offchain-worker\" or \"teeracle\" cannot be enabled at the same time"
);

pub mod worker_mode;

pub mod files {
	// used by worker
	pub static ENCLAVE_TOKEN: &str = "enclave.token";
	pub static ENCLAVE_FILE: &str = "enclave.signed.so";
	pub static SHIELDING_KEY_FILE: &str = "enclave-shielding-pubkey.json";
	pub static SIGNING_KEY_FILE: &str = "enclave-signing-pubkey.bin";
	/// sidechain database path
	pub static SIDECHAIN_STORAGE_PATH: &str = "sidechain_db";
	pub static SIDECHAIN_PURGE_INTERVAL: u64 = 7200; // purge sidechain every .. s
	pub static SIDECHAIN_PURGE_LIMIT: u64 = 100; // keep the last.. sidechainblocks when purging

	// used by enclave
	/// Path to the light-client db for the Integritee parentchain.
	pub const INTEGRITEE_PARENTCHAIN_LIGHT_CLIENT_DB_PATH: &str = "integritee_lcdb";

	/// Path to the light-client db for the Target A parentchain.
	pub const TARGET_A_PARENTCHAIN_LIGHT_CLIENT_DB_PATH: &str = "target_a_lcdb";

	pub const RA_DUMP_CERT_DER_FILE: &str = "ra_dump_cert.der";

	// used by worker and enclave
	pub const SHARDS_PATH: &str = "shards";

	#[cfg(feature = "production")]
	pub static RA_SPID_FILE: &str = "spid_production.txt";
	#[cfg(feature = "production")]
	pub static RA_API_KEY_FILE: &str = "key_production.txt";

	#[cfg(not(feature = "production"))]
	pub static RA_SPID_FILE: &str = "spid.txt";
	#[cfg(not(feature = "production"))]
	pub static RA_API_KEY_FILE: &str = "key.txt";

	pub const SPID_MIN_LENGTH: usize = 32;
	pub const STATE_SNAPSHOTS_CACHE_SIZE: usize = 4;
}

/// Settings concerning the worker
pub mod worker {
	// the maximum size of any extrinsic that the enclave will ever generate in B
	pub const EXTRINSIC_MAX_SIZE: usize = 13_000;
	// the maximum size of the header
	pub const HEADER_MAX_SIZE: usize = 200;
	// maximum size of shielding key
	pub const SHIELDING_KEY_SIZE: usize = 8192;
	// maximum size of signing key
	pub const SIGNING_KEY_SIZE: usize = 32;
	// size of the MR enclave
	pub const MR_ENCLAVE_SIZE: usize = 32;
	// Factors to tune the initial amount of enclave funding:
	// Should be set to a value that ensures that the enclave can register itself
	// and the worker can run for a certain time. Only for development.
	pub const EXISTENTIAL_DEPOSIT_FACTOR_FOR_INIT_FUNDS: u128 = 200_000;
	// Should be set to a value that ensures that the enclave can register itself
	// and that the worker can start.
	pub const REGISTERING_FEE_FACTOR_FOR_INIT_FUNDS: u128 = 10;
	// Should be set to a value that ensures that at least 2 sidechain blocks are finalized per
	// parentchain block.
	pub const BLOCK_NUMBER_FINALIZATION_DIFF: u64 = 20;
}

pub mod sidechain {
	use core::time::Duration;

	pub static SLOT_DURATION: Duration = Duration::from_millis(1000);
}

/// Settings concerning the enclave
pub mod enclave {}

/// Settings for the Teeracle
pub mod teeracle {
	use core::time::Duration;
	// Send extrinsic to update market exchange rate on the parentchain once per day
	pub static DEFAULT_MARKET_DATA_UPDATE_INTERVAL: Duration = ONE_DAY;

	pub static ONE_DAY: Duration = Duration::from_secs(86400);

	pub static THIRTY_MINUTES: Duration = Duration::from_secs(1800);
}
