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

use crate::{
	get_layer_two_nonce,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_identifiers, get_pair_from_str},
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use chrono::{Duration, Utc};
use ita_stf::{Getter, Index, TrustedCall, TrustedCallSigned};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use log::*;
use pallet_session_proxy::{SessionProxyCredentials, SessionProxyRole};
use sp_core::{crypto::Ss58Codec, Pair};
use std::boxed::Box;

#[derive(Parser)]
pub struct AddSessionProxyCommand {
	/// subject's AccountId in ss58check format. must have maintainer privilege
	account: String,

	/// session proxy seed as 0x-prefixed hex value
	seed: String,

	/// role. one of Any, NonTransfer, ReadBalance, ReadAny
	role: String,
}

impl AddSessionProxyCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let signer = get_pair_from_str(trusted_args, &self.account);
		info!("account ss58 is {}", signer.public().to_ss58check());
		let delegate = get_pair_from_str(trusted_args, &self.seed);
		println!("send trusted call add-session-proxy for {}", delegate.public().to_ss58check());

		let (mrenclave, shard) = get_identifiers(trusted_args);
		let nonce = get_layer_two_nonce!(signer, cli, trusted_args);

		let role = match self.role.as_str() {
			"Any" => SessionProxyRole::Any,
			"NonTransfer" => SessionProxyRole::NonTransfer,
			"ReadAny" => SessionProxyRole::ReadAny,
			"ReadBalance" => SessionProxyRole::ReadBalance,
			_ => todo!(),
		};
		// todo! make expiry an argument as soon as it will be enforced in enclave
		let expiry_time = Utc::now() + Duration::days(10);
		let expiry = Some(expiry_time.timestamp_millis() as u64);
		let seed = hex::decode(&self.seed[2..]).unwrap().as_slice().try_into().unwrap();
		let credentials = SessionProxyCredentials { role, expiry, seed };
		let top: TrustedOperation<TrustedCallSigned, Getter> = TrustedCall::add_session_proxy(
			signer.public().into(),
			delegate.public().into(),
			credentials,
		)
		.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);

		if trusted_args.direct {
			Ok(send_direct_request(cli, trusted_args, &top).map(|_| CliResultOk::None)?)
		} else {
			Ok(perform_trusted_operation::<()>(cli, trusted_args, &top)
				.map(|_| CliResultOk::None)?)
		}
	}
}
