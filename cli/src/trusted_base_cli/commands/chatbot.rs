/*
	Copyright 2021 Integritee AG

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
	get_basic_signing_info_from_args,
	llm_handler::LLMHandler,
	notes_handler::NotesHandler,
	trusted_cli::TrustedCli,
	trusted_command_utils::get_trusted_account_info,
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use codec::Decode;
use dotenv::dotenv;
use ita_stf::{
	Getter, ParentchainsInfo, PublicGetter, TrustedCall, TrustedCallSigned, STF_TX_FEE_UNIT_DIVIDER,
};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use log::{info, warn};
use pallet_notes::TrustedNote;
use prometheus::{register_counter, Encoder, TextEncoder};
use std::{env, time::Duration};
use tokio::time::sleep;
use warp::Filter;

#[derive(Parser)]
pub struct ChatbotCommand {
	/// chatbot AccountId in ss58check format. must have enough funds on shard
	account: String,
	/// probing interval in seconds. default is 3600 (1h)
	#[clap(long)]
	interval: Option<u64>,
	/// port to use for serving prometheus metrics. default is 9090
	#[clap(long)]
	prometheus_port: Option<u16>,
	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl ChatbotCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		dotenv().ok();
		let api_key = env::var("OPENAI_API_KEY").unwrap();
		let ai_briefing = env::var("OPENAI_SYSTEM_BRIEFING").unwrap();
		let (bot_account, signer, mrenclave, shard) =
			get_basic_signing_info_from_args!(self.account, self.session_proxy, cli, trusted_args);

		let interval = self.interval.unwrap_or(1);
		let messages_received_counter = register_counter!(
			"messages_receiver_counter",
			"Number of messages received since startup"
		)
		.unwrap();

		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
			PublicGetter::parentchains_info,
		));
		let parentchains_info: ParentchainsInfo =
			perform_trusted_operation(cli, trusted_args, &top).unwrap();
		let decimals = parentchains_info.get_shielding_target_decimals().unwrap_or(12);
		println!("Shielding target decimals: {}", decimals);

		// Create a Tokio runtime
		let rt = tokio::runtime::Runtime::new().unwrap();

		// Initialize the notes handler
		let mut notes_handler =
			NotesHandler::new(cli, trusted_args, bot_account.clone(), signer.clone());
		notes_handler.fetch_history();
		info!(
			"fetched existing conversation history with {} counterparties",
			notes_handler.conversation_counterparties.iter().count()
		);

		let llm_handler = LLMHandler::new(api_key);

		rt.block_on(async {
			// Start the Prometheus server
			let metrics_route = warp::path("metrics").map(move || {
				let encoder = TextEncoder::new();
				let metric_families = prometheus::gather();
				let mut buffer = Vec::new();
				encoder.encode(&metric_families, &mut buffer).unwrap();
				warp::http::Response::builder()
					.header("Content-Type", encoder.format_type())
					.body(buffer)
			});

			tokio::spawn(
				warp::serve(metrics_route)
					.run(([0, 0, 0, 0], self.prometheus_port.unwrap_or(9090))),
			);
			loop {
				let account_info =
					get_trusted_account_info(cli, trusted_args, &bot_account, &signer)
						.unwrap_or_default();
				let decimal_balance_free =
					account_info.data.free as f64 / 10u128.pow(decimals as u32) as f64;
				let nonce = account_info.nonce;

				notes_handler.update();

				for counterparty in notes_handler.conversation_counterparties.iter() {
					if decimal_balance_free < 2f64 / STF_TX_FEE_UNIT_DIVIDER as f64 {
						warn!("Account has insufficient funds to reply");
						continue
					};
					let conversation = notes_handler.conversation_with(&counterparty, None);
					let unanswered_notes =
						notes_handler.unanswered_conversation_with(&counterparty, None);
					if !unanswered_notes.is_empty() {
						messages_received_counter.inc_by(f64::from(unanswered_notes.len() as u32));
						println!(
							"Unanswered notes with {}: {}",
							counterparty,
							unanswered_notes.len()
						);
						// concatenate all unswerered notes
						let prompt = unanswered_notes
							.iter()
							.map(|note| {
								if let TrustedNote::SuccessfulTrustedCall(ref tc) = note.note {
									if let Ok(TrustedCall::send_note(_, _, msg)) =
										TrustedCall::decode(&mut tc.as_slice())
									{
										String::from_utf8(msg.clone())
											.unwrap_or_else(|_| "Invalid UTF-8".to_string())
									} else {
										"".into()
									}
								} else {
									"".into()
								}
							})
							.collect::<Vec<_>>()
							.join("\n");
						let prompt_reply = llm_handler
							.process_ai_prompt(
								prompt,
								ai_briefing.clone(),
								&bot_account,
								conversation,
							)
							.await;
						let top = TrustedCall::send_note(
							bot_account.clone(),
							counterparty.clone(),
							prompt_reply.clone().into(),
						)
						.sign(
							&KeyPair::Sr25519(Box::new(signer.clone())),
							nonce,
							&mrenclave,
							&shard,
						)
						.into_trusted_operation(trusted_args.direct);
						if send_direct_request(cli, trusted_args, &top).is_ok() {
							println!("Sent a reply: {}", prompt_reply);
						} else {
							println!("Failed to send echo");
						}
					}
				}
				println!("Sleeping for {} seconds", interval);
				sleep(Duration::from_secs(interval)).await;
			}
		});
		Ok(CliResultOk::None)
	}
}
