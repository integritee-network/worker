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
use sp_core::crypto::Ss58Codec;
use ita_stf::{Balance, Getter, GuessTheNumberInfo, PublicGetter, TrustedCallSigned};
use itp_stf_primitives::types::TrustedOperation;
use crate::{
    trusted_cli::TrustedCli, Cli, CliResult, CliResultOk,
};
use crate::trusted_operation::perform_trusted_operation;

#[derive(Parser)]
pub struct GetTotalIssuanceCommand {}

impl GetTotalIssuanceCommand {
    pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
        let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
            PublicGetter::total_issuance),
        );
        let issuance: Balance = perform_trusted_operation(cli, trusted_args, &top).unwrap();
        println!("{:?}", issuance);
        Ok(CliResultOk::Balance { balance: issuance })
    }
}