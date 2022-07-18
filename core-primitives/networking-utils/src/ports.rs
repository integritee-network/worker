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

use std::{net::TcpListener, ops::Range};

/// Gets the first available port in a range.
/// Returns None if no port in range is available.
///
pub fn get_available_port_in_range(mut port_range: Range<u16>) -> Option<u16> {
	port_range.find(|port| port_is_available(*port))
}

fn port_is_available(port: u16) -> bool {
	TcpListener::bind(("127.0.0.1", port)).is_ok()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::mem::drop;

	#[test]
	fn port_is_not_available_when_bound() {
		let available_port = get_available_port_in_range(12000..13000).unwrap();

		let tcp_listener = TcpListener::bind(("127.0.0.1", available_port)).unwrap();

		assert!(!port_is_available(available_port));

		drop(tcp_listener);

		assert!(port_is_available(available_port));
	}
}
