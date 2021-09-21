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

//! REST API Client, supporting SSL/TLS

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use http_req_sgx as http_req;
	pub use http_sgx as http;
	pub use thiserror_sgx as thiserror;
	pub use url_sgx as url;
}

pub mod error;
pub mod http_client;
pub mod http_client_builder;
pub mod rest_client;

#[cfg(test)]
pub mod mocks;

use crate::error::Error;
use std::string::String;

/// Type for URL query parameters.
///
/// Slice of tuples in which the first field is parameter name and second is value.
/// These parameters are used with `get_with` and `post_with` functions.
///
/// # Examples
/// The vector
/// ```ignore
/// vec![("param1", "1234"), ("param2", "abcd")]
/// ```
/// would be parsed to **param1=1234&param2=abcd** in the request URL.
pub type Query<'a> = [(&'a str, &'a str)];

/// Rest path builder trait for type.
///
/// Provides implementation for `rest_path` function that builds
/// type (and REST endpoint) specific API path from given parameter(s).
/// The built REST path is appended to the base URL given to `RestClient`.
/// If `Err` is returned, it is propagated directly to API caller.
pub trait RestPath<T> {
	/// Construct type specific REST API path from given parameters
	/// (e.g. "api/devices/1234").
	fn get_path(par: T) -> Result<String, Error>;
}

/// REST HTTP GET trait
///
/// Provides the GET verb for a REST API
pub trait RestGet {
	/// Plain GET request
	fn get<U, T>(&mut self, params: U) -> Result<T, Error>
	where
		T: serde::de::DeserializeOwned + RestPath<U>;

	/// GET request with query parameters.
	fn get_with<U, T>(&mut self, params: U, query: &Query<'_>) -> Result<T, Error>
	where
		T: serde::de::DeserializeOwned + RestPath<U>;
}

/// REST HTTP POST trait
///
/// Provides the POST verb for a REST API
pub trait RestPost {
	/// Plain POST request.
	fn post<U, T>(&mut self, params: U, data: &T) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>;

	/// Make POST request with query parameters.
	fn post_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>;

	/// Make a POST request and capture returned body.
	fn post_capture<U, T, K>(&mut self, params: U, data: &T) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned;

	/// Make a POST request with query parameters and capture returned body.
	fn post_capture_with<U, T, K>(
		&mut self,
		params: U,
		data: &T,
		query: &Query<'_>,
	) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned;
}

/// REST HTTP PUT trait
///
/// Provides the PUT verb for a REST API
pub trait RestPut {
	/// PUT request.
	fn put<U, T>(&mut self, params: U, data: &T) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>;

	/// Make PUT request with query parameters.
	fn put_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>;

	/// Make a PUT request and capture returned body.
	fn put_capture<U, T, K>(&mut self, params: U, data: &T) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned;

	/// Make a PUT request with query parameters and capture returned body.
	fn put_capture_with<U, T, K>(
		&mut self,
		params: U,
		data: &T,
		query: &Query<'_>,
	) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned;
}

/// REST HTTP PATCH trait
///
/// Provides the PATCH verb for a REST API
pub trait RestPatch {
	/// Make a PATCH request.
	fn patch<U, T>(&mut self, params: U, data: &T) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>;

	/// Make PATCH request with query parameters.
	fn patch_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>;
}

/// REST HTTP DELETE trait
///
/// Provides the DELETE verb for a REST API
pub trait RestDelete {
	/// Make a DELETE request.
	fn delete<U, T>(&mut self, params: U) -> Result<(), Error>
	where
		T: RestPath<U>;

	/// Make a DELETE request with query and body.
	fn delete_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>;
}
