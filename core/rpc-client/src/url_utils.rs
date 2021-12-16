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

use crate::error::{Error, Result};
use std::{num::ParseIntError, string::String};

/// Temporary method that transforms the workers rpc port of the direct api defined in rpc/direct_client
/// to the new version in rpc-server. Remove this, when all the methods have been migrated to the new one
/// in rpc-server.
pub fn worker_url_into_async_rpc_url(url: &str) -> Result<String> {
	// [Option("ws(s)"), //ip, port]
	let mut url_vec: Vec<&str> = url.split(':').collect();
	match url_vec.len() {
		3 | 2 => (),
		_ => return Err(Error::Custom("Invalid worker url format".into())),
	};

	let ip = if url_vec.len() == 3 {
		format!("{}:{}", url_vec.remove(0), url_vec.remove(0))
	} else {
		url_vec.remove(0).into()
	};

	let port: i32 =
		url_vec.remove(0).parse().map_err(|e: ParseIntError| Error::Custom(e.into()))?;

	Ok(format!("{}:{}", ip, (port + 1)))
}
