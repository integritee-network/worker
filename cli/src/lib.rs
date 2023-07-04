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

//! an RPC client to Integritee using websockets
//!
//! examples
//! integritee_cli 127.0.0.1:9944 transfer //Alice 5G9RtsTbiYJYQYMHbWfyPoeuuxNaCbC16tZ2JGrZ4gRKwz14 1000
//!
#![feature(rustc_private)]
#[macro_use]
extern crate clap;
extern crate chrono;
extern crate env_logger;
extern crate log;

mod attesteer;
mod base_cli;
mod benchmark;
mod command_utils;
mod error;
#[cfg(feature = "evm")]
mod evm;
#[cfg(feature = "teeracle")]
mod oracle;
mod trusted_base_cli;
mod trusted_cli;
mod trusted_command_utils;
mod trusted_operation;

pub mod commands;

use crate::commands::Commands;
use clap::Parser;
use sp_application_crypto::KeyTypeId;
use sp_core::{H160, H256};
use substrate_api_client::Metadata;
use thiserror::Error;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) const SR25519_KEY_TYPE: KeyTypeId = KeyTypeId(*b"sr25");
pub(crate) const ED25519_KEY_TYPE: KeyTypeId = KeyTypeId(*b"ed25");

#[derive(Parser)]
#[clap(name = "integritee-cli")]
#[clap(version = VERSION)]
#[clap(author = "Integritee AG <hello@integritee.network>")]
#[clap(about = "interact with integritee-node and workers", long_about = None)]
#[clap(after_help = "stf subcommands depend on the stf crate this has been built against")]
pub struct Cli {
	/// node url
	#[clap(short = 'u', long, default_value_t = String::from("ws://127.0.0.1"))]
	node_url: String,

	/// node port
	#[clap(short = 'p', long, default_value_t = String::from("9944"))]
	node_port: String,

	/// worker url
	#[clap(short = 'U', long, default_value_t = String::from("wss://127.0.0.1"))]
	worker_url: String,

	/// worker direct invocation port
	#[clap(short = 'P', long, default_value_t = String::from("2000"))]
	trusted_worker_port: String,

	#[clap(subcommand)]
	command: Commands,
}

pub enum CliResultOk {
	PubKeysBase58 {
		pubkeys_sr25519: Option<Vec<String>>,
		pubkeys_ed25519: Option<Vec<String>>,
	},
	Balance {
		balance: u128,
	},
	MrEnclaveBase58 {
		mr_enclaves: Vec<String>,
	},
	Metadata {
		metadata: Metadata,
	},
	H256 {
		hash: H256,
	},
	/// Result of "EvmCreateCommands": execution_address
	H160 {
		hash: H160,
	},
	// TODO should ideally be removed; or at least drastically less used
	// We WANT all commands exposed by the cli to return something useful for the caller(ie instead of printing)
	None,
}

#[derive(Debug, Error)]
pub enum CliError {
	#[error("trusted operation error: {:?}", msg)]
	TrustedOp { msg: String },
	#[error("EvmReadCommands error: {:?}", msg)]
	EvmRead { msg: String },
}

pub type CliResult = Result<CliResultOk, CliError>;

/// This is used for the commands that directly call `perform_trusted_operation`
/// which typically return `CliResultOk::None`
///
/// eg: `SetBalanceCommand`,`TransferCommand`,`UnshieldFundsCommand`
impl From<trusted_operation::TrustedOperationError> for CliError {
	fn from(value: trusted_operation::TrustedOperationError) -> Self {
		CliError::TrustedOp { msg: value.to_string() }
	}
}
