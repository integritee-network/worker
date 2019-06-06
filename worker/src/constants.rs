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

// pub const SECRET_KEY_SIZE: usize = 32;
pub static ENCLAVE_TOKEN: &'static str = "./bin/enclave.token";
pub static ENCLAVE_FILE:  &'static str = "./bin/enclave.signed.so";
pub static RSA_PUB_KEY:   &'static str = "./bin/rsa_pubkey.txt";
pub static ECC_PUB_KEY:   &'static str = "./bin/ecc_pubkey.txt";
