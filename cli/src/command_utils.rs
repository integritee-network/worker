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

use crate::Cli;
use base58::FromBase58;
use chrono::{DateTime, Local, NaiveDateTime};
use ita_parentchain_interface::integritee::{AccountId, Signature};
use itc_rpc_client::direct_client::{DirectApi, DirectClient as DirectWorkerApi};
use itp_node_api::api_client::{ParentchainApi, TungsteniteRpcClient};
use itp_types::Moment;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_application_crypto::sr25519;
use sp_core::{crypto::Ss58Codec, Pair};
use sp_runtime::traits::{IdentifyAccount, Verify};
use std::path::PathBuf;
use substrate_client_keystore::LocalKeystore;

type AccountPublic = <Signature as Verify>::Signer;
pub(crate) const KEYSTORE_PATH: &str = "my_keystore";

/// Retrieves the public shielding key via the enclave websocket server.
pub(crate) fn get_shielding_key(cli: &Cli) -> Result<Rsa3072PubKey, String> {
	let worker_api_direct = get_worker_api_direct(cli);
	worker_api_direct.get_rsa_pubkey().map_err(|e| e.to_string())
}

pub(crate) fn get_chain_api(cli: &Cli) -> ParentchainApi {
	let url = format!("{}:{}", cli.node_url, cli.node_port);
	info!("connecting to {}", url);
	ParentchainApi::new(TungsteniteRpcClient::new(&url, 5).unwrap()).unwrap()
}

pub(crate) fn get_accountid_from_str(account: &str) -> AccountId {
	match &account[..2] {
		"//" => AccountPublic::from(sr25519::Pair::from_string(account, None).unwrap().public())
			.into_account(),
		_ => AccountPublic::from(sr25519::Public::from_ss58check(account).unwrap()).into_account(),
	}
}

pub(crate) fn get_worker_api_direct(cli: &Cli) -> DirectWorkerApi {
	let url = format!("{}:{}", cli.worker_url, cli.trusted_worker_port);
	info!("Connecting to integritee-service-direct-port on '{}'", url);
	DirectWorkerApi::new(url)
}

/// get a pair either form keyring (well known keys) or from the store
pub(crate) fn get_pair_from_str(account: &str) -> sr25519::AppPair {
	info!("getting pair for {}", account);
	match &account[..2] {
		"//" => sr25519::AppPair::from_string(account, None).unwrap(),
		"0x" => sr25519::AppPair::from_string_with_seed(account, None).unwrap().0,
		_ => {
			if sr25519::Public::from_ss58check(account).is_err() {
				// could be mnemonic phrase
				return sr25519::AppPair::from_string_with_seed(account, None).unwrap().0
			}
			info!("fetching from keystore at {}", &KEYSTORE_PATH);
			// open store without password protection
			let store = LocalKeystore::open(PathBuf::from(&KEYSTORE_PATH), None)
				.expect("store should exist");
			info!("store opened");
			let maybe_pair = store
				.key_pair::<sr25519::AppPair>(
					&sr25519::Public::from_ss58check(account).unwrap().into(),
				)
				.unwrap();
			drop(store);
			match maybe_pair {
				Some(pair) => pair,
				None => panic!("account not in my_keystore"),
			}
		},
	}
}

pub(crate) fn mrenclave_from_base58(src: &str) -> [u8; 32] {
	let mut mrenclave = [0u8; 32];
	mrenclave.copy_from_slice(&src.from_base58().expect("mrenclave has to be base58 encoded"));
	mrenclave
}

pub(crate) fn format_moment(timestamp: Moment) -> String {
	let naive_datetime =
		NaiveDateTime::from_timestamp_millis(timestamp.try_into().unwrap()).unwrap();
	let datetime: DateTime<Local> = DateTime::from_utc(naive_datetime, *Local::now().offset());
	datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}
