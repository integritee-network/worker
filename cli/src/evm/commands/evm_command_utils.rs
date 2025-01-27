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
use crate::{trusted_cli::TrustedCli, trusted_operation::perform_trusted_operation, Cli};
use ita_stf::{Getter, TrustedCallSigned, TrustedGetter};
use itp_stf_primitives::types::{AccountId, KeyPair, Nonce, TrustedOperation};
use log::debug;
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};

/// Get the trusted EVM nonce for a given account
pub(crate) fn get_trusted_evm_nonce(
	cli: &Cli,
	trusted_args: &TrustedCli,
	subject: &AccountId,
	signer: &sr25519_core::Pair,
) -> Nonce {
	debug!(
		"get_trusted_evm_nonce: subject = {:?}, signer: {:?}",
		subject.to_ss58check(),
		signer.public().to_ss58check()
	);
	let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
		TrustedGetter::evm_nonce(subject.clone()).sign(&KeyPair::Sr25519(Box::new(signer.clone()))),
	));
	let maybe_nonce = perform_trusted_operation::<Nonce>(cli, trusted_args, &top).ok();
	debug!("get_trusted_evm_nonce: result: {:?}", maybe_nonce);
	maybe_nonce.unwrap_or_default()
}
