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

#![cfg_attr(test, feature(assert_matches))]
#![allow(unused)]

mod account_funding;
mod config;
mod enclave;
mod error;
mod globals;
mod initialized_service;
mod ocall_bridge;
mod parentchain_handler;
mod prometheus_metrics;
mod setup;
mod sidechain_setup;
mod sync_block_broadcaster;
mod sync_state;
#[cfg(feature = "teeracle")]
mod teeracle;
mod tests;
mod utils;
mod worker;
mod worker_peers_updater;

#[cfg(features = "link-binary")]
mod main_impl;

fn main() {
	#[cfg(features = "link-binary")]
	main_impl::main();

	#[cfg(not(features = "link-binary"))]
	panic!("tried to run the binary without linking. Make sure to pass `--feature link-binary`")
}
