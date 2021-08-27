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

use codec::Encode;
use log::*;
use sp_core::crypto::{AccountId32, Pair};
use sp_keyring::AccountKeyring;
use std::fs;
use substrate_api_client::XtStatus;

use my_node_runtime::Header;
use std::{thread::sleep, time::Duration};
use substrate_api_client::{compose_extrinsic, extrinsic::xt_primitives::UncheckedExtrinsicV4};
use substratee_node_primitives::{CallWorkerFn, Request, ShieldFundsFn};

use crate::tests::commons::*;
use substratee_api_client_extensions::TEEREX;
use substratee_enclave_api::{
	enclave_base::EnclaveBase, remote_attestation::RemoteAttestation, side_chain::SideChain,
};
use substratee_settings::files::SIGNING_KEY_FILE;

pub fn perform_ra_works<E: EnclaveBase + RemoteAttestation>(enclave_api: &E, port: &str) {
	// start the substrate-api-client to communicate with the node
	let (api, _nonce, _shard) = setup(enclave_api, Some(AccountKeyring::Alice), port);

	let w_url = "ws://127.0.0.1:2001";
	let genesis_hash = api.genesis_hash.as_bytes().to_vec();

	// get the public signing key of the TEE
	let mut key = [0; 32];
	let ecc_key = fs::read(SIGNING_KEY_FILE).expect("Unable to open ECC public key file");
	key.copy_from_slice(&ecc_key[..]);
	debug!("[+] Got ECC public key of TEE = {:?}", key);

	// get enclaves's account nonce
	let nonce = get_nonce(&api, &AccountId32::from(key));
	debug!("  TEE nonce is  {}", nonce);
	let _xt = enclave_api.perform_ra(genesis_hash, nonce, w_url.encode()).unwrap();
}

pub fn call_worker_encrypted_set_balance_works<E: EnclaveBase + SideChain>(
	enclave_api: &E,
	port: &str,
	last_synced_head: Header,
) -> Header {
	let root = AccountKeyring::Alice; // Alice is configure as root in our STF
	let (api, nonce, shard) = setup(enclave_api, Some(root), port);
	let req =
		Request { shard, cyphertext: encrypted_set_balance(enclave_api, root, nonce.unwrap()) };

	let xt: UncheckedExtrinsicV4<CallWorkerFn> =
		compose_extrinsic!(api, TEEREX, "call_worker", req);

	api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();

	println!("Sleeping until block with shield funds is finalized...");
	sleep(Duration::new(10, 0));
	println!("Syncing light client to look for shield_funds extrinsic");
	crate::produce_blocks(enclave_api, &api, last_synced_head)
}

pub fn forward_encrypted_unshield_works<E: EnclaveBase + SideChain>(
	enclave_api: &E,
	port: &str,
	last_synced_head: Header,
) -> Header {
	let (api, nonce, shard) = setup(enclave_api, Some(AccountKeyring::Alice), port);
	let req = Request {
		cyphertext: encrypted_unshield(enclave_api, AccountKeyring::Alice, nonce.unwrap()),
		shard,
	};

	let xt: UncheckedExtrinsicV4<CallWorkerFn> =
		compose_extrinsic!(api, TEEREX, "call_worker", req);

	api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();

	println!("Sleeping until block with shield funds is finalized...");
	sleep(Duration::new(10, 0));
	println!("Syncing light client to look for CallWorker with TrustedCall::unshield extrinsic");
	crate::produce_blocks(enclave_api, &api, last_synced_head)
}

pub fn init_light_client<E: EnclaveBase + SideChain>(port: &str, enclave_api: &E) -> Header {
	let (api, _, _) = setup(enclave_api, None, port);
	crate::init_light_client(&api, enclave_api)
}

pub fn shield_funds_workds<E: EnclaveBase + SideChain>(
	enclave_api: &E,
	port: &str,
	last_synced_head: Header,
) -> Header {
	let (api, _nonce, shard) = setup(enclave_api, Some(AccountKeyring::Alice), port);

	let xt: UncheckedExtrinsicV4<ShieldFundsFn> = compose_extrinsic!(
		api,
		"SubstrateeRegistry",
		"shield_funds",
		encrypted_alice(enclave_api),
		444u128,
		shard
	);
	let tx_hash = api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);

	println!("Sleeping until block with shield funds is finalized...");
	sleep(Duration::new(10, 0));
	println!("Syncing light client to look for shield_funds extrinsic");
	crate::produce_blocks(enclave_api, &api, last_synced_head)
}
