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
use ita_stf::{Getter, PublicGetter, TrustedCallSigned};
use itp_stf_primitives::types::TrustedOperation;
use crate::{
    trusted_cli::TrustedCli, Cli, CliResult, CliResultOk,
};
use crate::trusted_operation::perform_trusted_operation;

#[derive(Parser)]
pub struct GetLastLuckyNumberCommand {}

impl GetLastLuckyNumberCommand {
    pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
        let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
            PublicGetter::guess_the_number_last_lucky_number),
        );
        let lucky_number = perform_trusted_operation::<u32>(cli, trusted_args, &top).unwrap();
        println!("{}", lucky_number);
        Ok(CliResultOk::U32 { value: lucky_number })
    }
}
