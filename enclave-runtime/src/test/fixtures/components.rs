/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::test::mocks::types::{TestOCallApi, TestRpcResponder, TestSigner, TestTopPool};
use codec::Encode;
use ita_stf::{TrustedCall, TrustedCallSigned, TrustedOperation};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::ShieldingCryptoEncrypt;
use itp_stf_primitives::types::KeyPair;
use itp_top_pool::pool::Options as PoolOptions;
use itp_top_pool_author::api::SidechainApi;
use itp_types::{Block as ParentchainBlock, Enclave, ShardIdentifier};
use sp_core::{ed25519, Pair, H256};
use sp_runtime::traits::Header as HeaderTrait;
use std::{boxed::Box, sync::Arc, vec::Vec};

pub(crate) fn create_top_pool() -> Arc<TestTopPool> {
	let rpc_responder = Arc::new(TestRpcResponder::new());
	let sidechain_api = Arc::new(SidechainApi::<ParentchainBlock>::new());
	Arc::new(TestTopPool::create(PoolOptions::default(), sidechain_api, rpc_responder))
}

pub(crate) fn create_ocall_api<Header: HeaderTrait<Hash = H256>>(
	header: &Header,
	signer: &TestSigner,
) -> Arc<TestOCallApi> {
	let enclave_validateer = Enclave::new(
		signer.public().into(),
		Default::default(),
		Default::default(),
		Default::default(),
	);
	Arc::new(TestOCallApi::default().add_validateer_set(header, Some(vec![enclave_validateer])))
}

pub(crate) fn encrypt_trusted_operation<ShieldingKey: ShieldingCryptoEncrypt>(
	shielding_key: &ShieldingKey,
	trusted_operation: &TrustedOperation,
) -> Vec<u8> {
	let encoded_operation = trusted_operation.encode();
	shielding_key.encrypt(encoded_operation.as_slice()).unwrap()
}

pub(crate) fn sign_trusted_call<AttestationApi: EnclaveAttestationOCallApi>(
	trusted_call: &TrustedCall,
	attestation_api: &AttestationApi,
	shard_id: &ShardIdentifier,
	from: ed25519::Pair,
) -> TrustedCallSigned {
	let mr_enclave = attestation_api.get_mrenclave_of_self().unwrap();
	trusted_call.sign(&KeyPair::Ed25519(Box::new(from)), 0, &mr_enclave.m, shard_id)
}
