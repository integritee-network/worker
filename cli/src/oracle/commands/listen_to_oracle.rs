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

use crate::{command_utils::get_chain_api, Cli};
use codec::Decode;
use itp_node_api::api_client::ParentchainApi;
use itp_time_utils::{duration_now, remaining_time};
use log::{debug, info};
use my_node_runtime::{Event, Hash, pallet_teeracle};
use std::{sync::mpsc::channel, time::Duration};
use substrate_api_client::FromHexString;

/// Listen to exchange rate events.
#[derive(Debug, Clone, Parser)]
pub struct ListenToOracleEventsCmd {
	/// Listen for `duration` in seconds.
	duration: u64,
}

type EventCount = u32;

impl ListenToOracleEventsCmd {
    pub fn run(&self, cli: &Cli) {
        let api = get_chain_api(cli);
        let duration = Duration::from_secs(self.duration);
        let count = count_oracle_update_events(&api, duration);
        println!("Number of Oracle events received : ");
		println!("   EVENTS_COUNT: {}", count);
    }
}

fn count_oracle_update_events(api: &ParentchainApi, duration: Duration) -> EventCount {
    0u32
}