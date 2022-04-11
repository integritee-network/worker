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

use crate::tests::commons::test_trusted_getter_signed;
use codec::Encode;
use itp_enclave_api::{enclave_base::EnclaveBase, EnclaveResult};
use itp_stf_state_handler::file_io::purge_shard_dir;
use log::*;
use sp_core::hash::H256;
use sp_keyring::AccountKeyring;

pub fn get_state_works<E: EnclaveBase>(enclave_api: &E) -> EnclaveResult<()> {
	let alice = AccountKeyring::Alice;
	let trusted_getter_signed = test_trusted_getter_signed(alice).encode();
	let shard = H256::default();
	enclave_api.init_shard(shard.encode())?;
	let res = enclave_api.get_state(trusted_getter_signed, shard.encode())?;
	debug!("got state value: {:?}", hex::encode(res.clone()));
	//println!("get_state returned {:?}", res);

	assert!(!res.is_empty());

	purge_shard_dir(&shard);

	Ok(())
}
