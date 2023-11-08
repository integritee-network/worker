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

use codec::Encode;
use itp_stf_primitives::types::ShardIdentifier;

use sp_core::{ed25519, Pair};
use sp_runtime::traits::{BlakeTwo256, Hash};
use std::vec;

type Seed = [u8; 32];
const TEST_SEED: Seed = *b"12345678901234567890123456789012";

pub(crate) fn mr_enclave() -> [u8; 32] {
	[1u8; 32]
}

pub(crate) fn shard_id() -> ShardIdentifier {
	BlakeTwo256::hash(vec![1u8, 2u8, 3u8].as_slice().encode().as_slice())
}

fn alice_pair() -> ed25519::Pair {
	ed25519::Pair::from_seed(b"22222678901234567890123456789012")
}

fn bob_pair() -> ed25519::Pair {
	ed25519::Pair::from_seed(b"33333378901234567890123456789012")
}
