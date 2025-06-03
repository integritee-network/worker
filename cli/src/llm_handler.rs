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

use codec::Decode;
use ita_stf::TrustedCall;
use itp_types::{AccountId, Moment};
use log::{debug, trace, warn};
use pallet_notes::{TimestampedTrustedNote, TrustedNote};
use reqwest::Client;
use serde::{Deserialize, Serialize};

// ChatGPT API types
#[derive(Serialize)]
struct ChatRequest<'a> {
	model: &'a str,
	messages: Vec<Message<'a>>,
	max_tokens: u16,
}

#[derive(Debug, Serialize)]
struct Message<'a> {
	role: &'a str,
	content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
	choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
	message: MessageContent,
}

#[derive(Deserialize)]
struct MessageContent {
	content: String,
}

pub struct LLMHandler {
	api_key: String,
}

impl LLMHandler {
	pub fn new(api_key: String) -> Self {
		LLMHandler { api_key }
	}

	pub async fn process_ai_prompt(
		&self,
		prompt: String,
		system_briefing: String,
		bot_account: &AccountId,
		history: Vec<TimestampedTrustedNote<Moment>>,
	) -> String {
		let mut messages: Vec<Message> =
			vec![Message { role: "system", content: system_briefing.as_str() }];
		history.iter().for_each(|note| {
			if let TrustedNote::SuccessfulTrustedCall(ref tc) = note.note {
				if let Ok(TrustedCall::send_note(from, _to, msg)) =
					TrustedCall::decode(&mut tc.as_slice())
				{
					let msg_str = String::from_utf8(msg).unwrap_or_else(|_| {
						warn!("Failed to decode message as UTF-8, using empty string");
						String::new()
					});
					if *bot_account == from {
						messages.push(Message {
							role: "assistant",
							content: Box::leak(msg_str.into_boxed_str()),
						});
					} else {
						messages.push(Message {
							role: "user",
							content: Box::leak(msg_str.into_boxed_str()),
						});
					}
				}
			}
		});
		messages.push(Message { role: "user", content: prompt.as_str() });
		trace!("Sending prompt to LLM: {:?}", messages);
		let request_body = ChatRequest {
			model: "gpt-4.1-nano-2025-04-14",
			messages,
			max_tokens: 70, // Roughly ≈ 140 characters
		};
		let client = Client::new();
		let response = client
			.post("https://api.openai.com/v1/chat/completions")
			.bearer_auth(self.api_key.clone())
			.json(&request_body)
			.send()
			.await
			.unwrap();
		debug!("Got response from LLM: {:?}", response);
		let json: ChatResponse = response.json().await.unwrap();
		let prompt_reply = {
			let content = json.choices[0].message.content.trim();
			let cropped = &content.as_bytes()[..std::cmp::min(200, content.len())];
			String::from_utf8_lossy(cropped).to_string()
		};
		prompt_reply
	}
}
