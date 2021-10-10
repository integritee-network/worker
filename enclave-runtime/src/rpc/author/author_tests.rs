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

#[cfg(feature = "test")]
pub mod tests {
	use crate::{
		rpc::author::{Author, AuthorApi},
		state::HandleState,
		test::mocks::{
			handle_state_mock::HandleStateMock, shielding_crypto_mock::ShieldingCryptoMock,
			trusted_operation_pool_mock::TrustedOperationPoolMock,
		},
	};
	use codec::Encode;
	use frame_support::sp_runtime::traits::{BlakeTwo256, Hash};
	use ita_stf::{Getter, KeyPair, ShardIdentifier, TrustedGetter, TrustedOperation};
	use itp_sgx_crypto::ShieldingCrypto;
	use jsonrpc_core::futures::executor;
	use sp_core::{ed25519, Pair, H256};
	use std::sync::Arc;

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	pub fn submitting_to_author_inserts_in_pool() {
		let top_pool = Arc::new(TrustedOperationPoolMock::default());

		let shard_id = shard_id();
		let mut state_facade = HandleStateMock::default();
		state_facade.init_shard(&shard_id).unwrap();

		let encryption_key = ShieldingCryptoMock::default();

		let author = Author::new(top_pool.clone(), Arc::new(state_facade), encryption_key.clone());
		let top = TrustedOperation::from(trusted_getter_signed());
		let top_encrypted = encryption_key.encrypt(top.encode().as_slice()).unwrap();

		let submit_future = async { author.submit_top(top_encrypted, shard_id).await };
		let submit_response: H256 = executor::block_on(submit_future).unwrap();

		assert!(!submit_response.is_zero());

		let submitted_transactions = top_pool.get_last_submitted_transactions();
		assert_eq!(1, submitted_transactions.len());
	}

	fn trusted_getter_signed() -> Getter {
		let who_key_pair = ed25519::Pair::from_seed(&TEST_SEED);
		let getter = TrustedGetter::free_balance(who_key_pair.public().into());
		Getter::trusted(getter.sign(&KeyPair::Ed25519(who_key_pair)))
	}

	fn shard_id() -> ShardIdentifier {
		BlakeTwo256::hash(vec![1u8, 2u8, 3u8].as_slice().encode().as_slice())
	}
}
