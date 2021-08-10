/*
	Copyright 2019 Supercomputing Systems AG

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

use crate::{enclave_account, ensure_account_has_funds};
use base58::ToBase58;
use codec::Encode;
use log::*;
use serde_derive::{Deserialize, Serialize};
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use sp_core::{crypto::AccountId32, sr25519};
use sp_keyring::AccountKeyring;
use std::{fs, str};
use substrate_api_client::{rpc::WsRpcClient, Api};
use substratee_enclave_api::enclave_base::EnclaveBase;
use substratee_stf::{Getter, Index, KeyPair, ShardIdentifier, TrustedCall, TrustedGetter};

#[cfg(test)]
use crate::config::Config;
#[cfg(test)]
use substratee_worker_primitives::{
	block::{Block, SignedBlock},
	traits::{Block as BlockT, SignBlock},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
	pub account: String,
	pub amount: u32,
	pub sha256: sgx_sha256_hash_t,
}

/// Who must be root account
pub fn encrypted_set_balance<E: EnclaveBase>(
	enclave_api: &E,
	who: AccountKeyring,
	nonce: Index,
) -> Vec<u8> {
	info!("*** Get the public key from the TEE\n");
	let rsa_pubkey: Rsa3072PubKey = enclave_api.get_rsa_shielding_pubkey().unwrap();
	info!("deserialized rsa key");

	let call = TrustedCall::balance_set_balance(who.public().into(), who.public().into(), 33, 44);
	encrypt_payload(
		rsa_pubkey,
		call.sign(
			&KeyPair::Sr25519(who.pair()),
			nonce,
			&enclave_api.get_mrenclave().unwrap(),
			&ShardIdentifier::default(),
		)
		.encode(),
	)
}

pub fn encrypted_unshield<E: EnclaveBase>(
	enclave_api: &E,
	who: AccountKeyring,
	nonce: Index,
) -> Vec<u8> {
	info!("*** Get the public key from the TEE\n");
	let rsa_pubkey: Rsa3072PubKey = enclave_api.get_rsa_shielding_pubkey().unwrap();
	info!("deserialized rsa key");

	let call = TrustedCall::balance_unshield(
		who.public().into(),
		who.public().into(),
		40,
		ShardIdentifier::default(),
	);
	encrypt_payload(
		rsa_pubkey,
		call.sign(
			&KeyPair::Sr25519(who.pair()),
			nonce,
			&enclave_api.get_mrenclave().unwrap(),
			&ShardIdentifier::default(),
		)
		.encode(),
	)
}

pub fn encrypt_payload(rsa_pubkey: Rsa3072PubKey, payload: Vec<u8>) -> Vec<u8> {
	let mut payload_encrypted: Vec<u8> = Vec::new();
	rsa_pubkey.encrypt_buffer(&payload, &mut payload_encrypted).unwrap();
	payload_encrypted
}

pub fn test_trusted_getter_signed(who: AccountKeyring) -> Getter {
	let getter = TrustedGetter::free_balance(who.public().into());
	Getter::trusted(getter.sign(&KeyPair::Sr25519(who.pair())))
}

pub fn encrypted_alice<E: EnclaveBase>(enclave_api: &E) -> Vec<u8> {
	info!("*** Get the public key from the TEE\n");
	let rsa_pubkey: Rsa3072PubKey = enclave_api.get_rsa_shielding_pubkey().unwrap();
	encrypt_payload(rsa_pubkey, AccountKeyring::Alice.encode())
}

pub fn setup<E: EnclaveBase>(
	enclave_api: &E,
	who: Option<AccountKeyring>,
	port: &str,
) -> (Api<sr25519::Pair, WsRpcClient>, Option<u32>, ShardIdentifier) {
	let node_url = format!("ws://{}:{}", "127.0.0.1", port);
	let mut api = Api::<sr25519::Pair, WsRpcClient>::new(WsRpcClient::new(&node_url)).unwrap();
	ensure_account_has_funds(&mut api, &enclave_account(enclave_api));

	// create the state such that we do not need to initialize it manually
	let shard = ShardIdentifier::default();
	let path = "./shards/".to_owned() + &shard.encode().to_base58();
	fs::create_dir_all(&path).unwrap();
	fs::File::create(path + "/state.bin").unwrap();

	match who {
		Some(account) => {
			api = api.set_signer(account.pair());
			let nonce = get_nonce(&api, &account.to_account_id());
			(api, Some(nonce), shard)
		},
		None => (api, None, shard),
	}
}

pub fn get_nonce(api: &Api<sr25519::Pair, WsRpcClient>, who: &AccountId32) -> u32 {
	if let Some(info) = api.get_account_info(who).unwrap() {
		info.nonce
	} else {
		0
	}
}

#[cfg(test)]
pub fn test_sidechain_block() -> SignedBlock {
	use sp_core::{Pair, H256};

	let signer_pair = sp_core::ed25519::Pair::from_string("//Alice", None).unwrap();
	let author: AccountId32 = signer_pair.public().into();
	let block_number: u64 = 0;
	let parent_hash = H256::random();
	let layer_one_head = H256::random();
	let signed_top_hashes = vec![];
	let encrypted_payload: Vec<u8> = vec![];
	let shard = ShardIdentifier::default();

	// when
	let block = Block::new(
		author,
		block_number,
		parent_hash.clone(),
		layer_one_head.clone(),
		shard.clone(),
		signed_top_hashes.clone(),
		encrypted_payload.clone(),
		1000,
	);
	block.sign_block(&signer_pair)
}

/// Local Worker config. Fields are the default values except for
/// the worker's rpc server.
#[cfg(test)]
pub fn local_worker_config(worker_url: String) -> Config {
	let mut url = worker_url.split(":");
	Config::new(
		Default::default(),
		Default::default(),
		url.next().unwrap().into(),
		url.next().unwrap().into(),
		Default::default(),
	)
}
