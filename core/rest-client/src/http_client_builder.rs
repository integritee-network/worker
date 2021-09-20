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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::http_client::HttpClient;
use http_req::response::Headers;
use std::{string::String, time::Duration};

/// Builder for `HttpClient`
pub struct HttpClientBuilder {
	/// Request timeout
	timeout: Duration,

	/// Send null body
	send_null_body: bool,

	/// pre-set headers
	headers: Option<Headers>,

	/// authorization
	authorization: Option<String>,
}

impl Default for HttpClientBuilder {
	fn default() -> Self {
		Self {
			timeout: Duration::from_secs(u64::MAX),
			send_null_body: true,
			headers: None,
			authorization: None,
		}
	}
}

impl HttpClientBuilder {
	/// Set request timeout
	///
	/// Default is no timeout
	pub fn timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Send null body in POST/PUT
	///
	/// Default is yes
	pub fn send_null_body(mut self, value: bool) -> Self {
		self.send_null_body = value;
		self
	}

	/// Pre-set headers to attach to each request
	///
	/// default is none
	pub fn headers(mut self, headers: Headers) -> Self {
		self.headers = Some(headers);
		self
	}

	/// Basic HTTP authorization (format: `username:password`)
	///
	/// default is none
	pub fn authorization(mut self, authorization: String) -> Self {
		self.authorization = Some(authorization);
		self
	}

	/// Create `HttpClient` with the configuration in this builder
	pub fn build(self) -> HttpClient {
		HttpClient::new(self.send_null_body, Some(self.timeout), self.headers, self.authorization)
	}
}
