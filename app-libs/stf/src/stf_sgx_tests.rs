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

use crate::Stf;
use sp_core::{ed25519::Pair as spEd25519Pair, Pair};
use sp_runtime::traits::Verify;

pub fn enclave_account_signing_works() {
	let mut state = Stf::init_state();
	let payload = [3u8; 45];

	let enclave_account = Stf::get_enclave_account(&mut state).unwrap();
	let enclave_account_nonce = Stf::account_nonce(&mut state, &enclave_account);

	let payload_signature = Stf::sign_with_enclave_account(&mut state, &payload);

	assert_eq!(0, enclave_account_nonce);
	assert!(payload_signature.verify(&payload, sp_core::ed25519::Public::from_raw(enclave_account)));
}
