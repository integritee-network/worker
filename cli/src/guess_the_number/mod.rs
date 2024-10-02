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
    trusted_cli::TrustedCli,
    Cli, CliResult,
};
use commands::get_info::GetInfoCommand;
use commands::set_winnings::SetWinningsCommand;
use commands::push_by_one_day::PushByOneDayCommand;
use commands::guess::GuessCommand;

mod commands;

#[derive(Subcommand)]
pub enum GuessTheNumberCommand {
    /// get public info for the guess-the-number game
    GetInfo(GetInfoCommand),
    /// set winnings amount (must be game master)
    SetWinnings(SetWinningsCommand),
    /// push the end of this round by one day (must be game master)
    PushByOneDay(PushByOneDayCommand),
    /// submit a guess as a player
    Guess(GuessCommand),
}

impl GuessTheNumberCommand {
    pub fn run(&self, cli: &Cli, trusted_cli: &TrustedCli) -> CliResult {
        match self {
            GuessTheNumberCommand::GetInfo(cmd) => cmd.run(cli, trusted_cli),
            GuessTheNumberCommand::SetWinnings(cmd) => cmd.run(cli, trusted_cli),
            GuessTheNumberCommand::PushByOneDay(cmd) => cmd.run(cli, trusted_cli),
            GuessTheNumberCommand::Guess(cmd) => cmd.run(cli, trusted_cli),
        }
    }
}
