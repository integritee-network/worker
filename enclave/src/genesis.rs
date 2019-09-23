use std::vec::Vec;

//use my_node_runtime::{Hash, AccountId, AuthorityId};
use runtime_primitives::{AnySignature, traits::Verify};
//FIXME: move this to runtime_wrapper
pub type Signature = AnySignature;
pub type AuthorityId = <Signature as Verify>::Signer;
pub type AccountId = <Signature as Verify>::Signer;
pub type Hash = primitives::H256;

use primitive_types::U128;


//use substrate_service;

//#[derive(Serialize, Deserialize)]
//#[serde(rename_all = "camelCase")]
//#[serde(deny_unknown_fields)]
pub struct GenesisConfig {
	consensus: Option<ConsensusConfig>,
 	timestamp: Option<TimestampConfig>,
	balances: Option<BalancesConfig>,
	indices: Option<IndicesConfig>,
	sudo: Option<SudoConfig>,
	system: Option<()>,
}

struct ConsensusConfig {
			code: Vec<u8>,
			authorities: Vec<AuthorityId>,
		}

struct TimestampConfig {
			minimum_period: u32, // 10 second block time.
		}
struct IndicesConfig {
			ids: Vec<AccountId>,
		}
struct BalancesConfig {
			transaction_base_fee: u128,
			transaction_byte_fee: u128,
			existential_deposit: u128,
			transfer_fee: u128,
			creation_fee: u128,
			balances: Vec<(AccountId, u128)>,
			vesting: Vec<u8>,
		}


struct SudoConfig {
			key: AccountId,
		}




//use ed25519::Public as AuthorityId;

// Note this is the URL for the telemetry server
//const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
//pub type ChainSpec = substrate_service::ChainSpec<GenesisConfig>;

/*
/// The chain specification option. This is expected to come in from the CLI and
/// is little more than one of a number of alternatives which can easily be converted
/// from a string (`--chain=...`) into a `ChainSpec`.
#[derive(Clone, Debug)]
pub enum Alternative {
	/// Whatever the current runtime is, with just Alice as an auth.
	Development,
	/// Whatever the current runtime is, with simple Alice/Bob auths.
	LocalTestnet,
}

fn authority_key(s: &str) -> AuthorityId {
	ed25519::Pair::from_string(&format!("//{}", s), None)
		.expect("static values are valid; qed")
		.public()
}

fn account_key(s: &str) -> AccountId {
	ed25519::Pair::from_string(&format!("//{}", s), None)
		.expect("static values are valid; qed")
		.public()
}

impl Alternative {
	/// Get an actual chain config from one of the alternatives.
	pub(crate) fn load(self) -> Result<ChainSpec, String> {
		Ok(match self {
			Alternative::Development => ChainSpec::from_genesis(
				"Development",
				"dev",
				|| testnet_genesis(vec![
					authority_key("Alice")
				], vec![
					account_key("Alice")
				],
					account_key("Alice")
				),
				vec![],
				None,
				None,
				None,
				None
			),
			Alternative::LocalTestnet => ChainSpec::from_genesis(
				"Local Testnet",
				"local_testnet",
				|| testnet_genesis(vec![
					authority_key("Alice"),
					authority_key("Bob"),
				], vec![
					account_key("Alice"),
					account_key("Bob"),
					account_key("Charlie"),
					account_key("Dave"),
					account_key("Eve"),
					account_key("Ferdie"),
				],
					account_key("Alice"),
				),
				vec![],
				None,
				None,
				None,
				None
			),
		})
	}

	pub(crate) fn from(s: &str) -> Option<Self> {
		match s {
			"dev" => Some(Alternative::Development),
			"" | "local" => Some(Alternative::LocalTestnet),
			_ => None,
		}
	}
}
*/
pub fn testnet_genesis(initial_authorities: Vec<AuthorityId>, endowed_accounts: Vec<AccountId>, root_key: AccountId) -> GenesisConfig {
	const MILLICENTS: u128 = 1_000_000_000;
	const CENTS: u128 = 1_000 * MILLICENTS;    // assume this is worth about a cent.

	GenesisConfig {
		consensus: Some(ConsensusConfig {
			code: vec!(0),
			authorities: initial_authorities.clone(),
		}),
		system: None,
		timestamp: Some(TimestampConfig {
			minimum_period: 5, // 10 second block time.
		}),
		indices: Some(IndicesConfig {
			ids: endowed_accounts.clone(),
		}),
		balances: Some(BalancesConfig {
			transaction_base_fee: 0,
			transaction_byte_fee: 0,
			existential_deposit: 0,
			transfer_fee: 0,
			creation_fee: 0,
			balances: endowed_accounts.iter().cloned().map(|k|(k, 1 << 60)).collect(),
			vesting: vec![],
		}),
		sudo: Some(SudoConfig {
			key: root_key,
		}),
	}
}
