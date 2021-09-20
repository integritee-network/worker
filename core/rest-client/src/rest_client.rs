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

use crate::{
	error::Error, http_client::SendHttpRequest, Query, RestDelete, RestGet, RestPatch, RestPath,
	RestPost, RestPut,
};
use http_req::{request::Method, response::Headers};
use log::*;
use std::string::{String, ToString};
use url::Url;

/// REST client to make HTTP GET and POST requests.
pub struct RestClient<H> {
	http_client: H,
	baseurl: Url,
	response_headers: Headers,
	body_wash_fn: fn(String) -> String,
}

impl<H> RestClient<H>
where
	H: SendHttpRequest,
{
	/// Construct new client with default configuration to make HTTP requests.
	///
	/// Use `Builder` to configure the client.
	pub fn new(http_client: H, baseurl: Url) -> Self {
		RestClient {
			http_client,
			baseurl,
			response_headers: Headers::new(),
			body_wash_fn: std::convert::identity,
		}
	}

	/// Set a function that cleans the response body up before deserializing it.
	pub fn set_body_wash_fn(&mut self, func: fn(String) -> String) {
		self.body_wash_fn = func;
	}

	/// Response headers captured from previous request
	pub fn response_headers(&mut self) -> &Headers {
		&self.response_headers
	}

	fn post_or_put<U, T>(&mut self, method: Method, params: U, data: &T) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		let data = serde_json::to_string(data).map_err(Error::SerializeParseError)?;

		let _body = self.make_request::<U, T>(method, params, None, Some(data))?;
		Ok(())
	}

	fn post_or_put_with<U, T>(
		&mut self,
		method: Method,
		params: U,
		data: &T,
		query: &Query<'_>,
	) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		let data = serde_json::to_string(data).map_err(Error::SerializeParseError)?;

		let _body = self.make_request::<U, T>(method, params, Some(query), Some(data))?;
		Ok(())
	}

	fn post_or_put_capture<U, T, K>(
		&mut self,
		method: Method,
		params: U,
		data: &T,
	) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned,
	{
		let data = serde_json::to_string(data).map_err(Error::SerializeParseError)?;

		let body = self.make_request::<U, T>(method, params, None, Some(data))?;
		serde_json::from_str(body.as_str()).map_err(|err| Error::DeserializeParseError(err, body))
	}

	fn post_or_put_capture_with<U, T, K>(
		&mut self,
		method: Method,
		params: U,
		data: &T,
		query: &Query<'_>,
	) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned,
	{
		let data = serde_json::to_string(data).map_err(Error::SerializeParseError)?;

		let body = self.make_request::<U, T>(method, params, Some(query), Some(data))?;
		serde_json::from_str(body.as_str()).map_err(|err| Error::DeserializeParseError(err, body))
	}

	fn make_request<U, T>(
		&mut self,
		method: Method,
		params: U,
		query: Option<&Query<'_>>,
		maybe_body: Option<String>,
	) -> Result<String, Error>
	where
		T: RestPath<U>,
	{
		let (response, encoded_body) = self.http_client.send_request::<U, T>(
			self.baseurl.clone(),
			method,
			params,
			query,
			maybe_body,
		)?;

		self.response_headers = response.headers().clone();
		let status_code = response.status_code();

		if !status_code.is_success() {
			let status_code_num = u16::from(status_code);
			let reason = String::from(status_code.reason().unwrap_or("none"));
			return Err(Error::HttpError(status_code_num, reason))
		}

		let body = String::from_utf8_lossy(&encoded_body).to_string();

		trace!("response headers: {:?}", self.response_headers);
		trace!("response body: {}", body);
		Ok((self.body_wash_fn)(body))
	}
}

impl<H> RestGet for RestClient<H>
where
	H: SendHttpRequest,
{
	/// Make a GET request.
	fn get<U, T>(&mut self, params: U) -> Result<T, Error>
	where
		T: serde::de::DeserializeOwned + RestPath<U>,
	{
		let body = self.make_request::<U, T>(Method::GET, params, None, None)?;

		serde_json::from_str(body.as_str()).map_err(|err| Error::DeserializeParseError(err, body))
	}

	/// Make a GET request with query parameters.
	fn get_with<U, T>(&mut self, params: U, query: &Query<'_>) -> Result<T, Error>
	where
		T: serde::de::DeserializeOwned + RestPath<U>,
	{
		let body = self.make_request::<U, T>(Method::GET, params, Some(query), None)?;

		serde_json::from_str(body.as_str()).map_err(|err| Error::DeserializeParseError(err, body))
	}
}

impl<H> RestPost for RestClient<H>
where
	H: SendHttpRequest,
{
	/// Make a POST request.
	fn post<U, T>(&mut self, params: U, data: &T) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		self.post_or_put(Method::POST, params, data)
	}

	/// Make POST request with query parameters.
	fn post_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		self.post_or_put_with(Method::POST, params, data, query)
	}

	/// Make a POST request and capture returned body.
	fn post_capture<U, T, K>(&mut self, params: U, data: &T) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned,
	{
		self.post_or_put_capture(Method::POST, params, data)
	}

	/// Make a POST request with query parameters and capture returned body.
	fn post_capture_with<U, T, K>(
		&mut self,
		params: U,
		data: &T,
		query: &Query<'_>,
	) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned,
	{
		self.post_or_put_capture_with(Method::POST, params, data, query)
	}
}

impl<H> RestPut for RestClient<H>
where
	H: SendHttpRequest,
{
	/// Make a PUT request.
	fn put<U, T>(&mut self, params: U, data: &T) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		self.post_or_put(Method::PUT, params, data)
	}

	/// Make PUT request with query parameters.
	fn put_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		self.post_or_put_with(Method::PUT, params, data, query)
	}

	/// Make a PUT request and capture returned body.
	fn put_capture<U, T, K>(&mut self, params: U, data: &T) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned,
	{
		self.post_or_put_capture(Method::PUT, params, data)
	}

	/// Make a PUT request with query parameters and capture returned body.
	fn put_capture_with<U, T, K>(
		&mut self,
		params: U,
		data: &T,
		query: &Query<'_>,
	) -> Result<K, Error>
	where
		T: serde::Serialize + RestPath<U>,
		K: serde::de::DeserializeOwned,
	{
		self.post_or_put_capture_with(Method::PUT, params, data, query)
	}
}

impl<H> RestPatch for RestClient<H>
where
	H: SendHttpRequest,
{
	/// Make a PATCH request.
	fn patch<U, T>(&mut self, params: U, data: &T) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		self.post_or_put(Method::PATCH, params, data)
	}

	/// Make PATCH request with query parameters.
	fn patch_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		self.post_or_put_with(Method::PATCH, params, data, query)
	}
}

impl<H> RestDelete for RestClient<H>
where
	H: SendHttpRequest,
{
	/// Make a DELETE request.
	fn delete<U, T>(&mut self, params: U) -> Result<(), Error>
	where
		T: RestPath<U>,
	{
		self.make_request::<U, T>(Method::DELETE, params, None, None)?;
		Ok(())
	}

	/// Make a DELETE request with query and body.
	fn delete_with<U, T>(&mut self, params: U, data: &T, query: &Query<'_>) -> Result<(), Error>
	where
		T: serde::Serialize + RestPath<U>,
	{
		let data = serde_json::to_string(data).map_err(Error::SerializeParseError)?;
		self.make_request::<U, T>(Method::DELETE, params, Some(query), Some(data))?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::mocks::http_client_mock::{HttpClientMock, ResponseBodyMock};

	#[test]
	pub fn get_sends_proper_request() {
		let mut rest_client = create_default_rest_client();

		let get_response =
			rest_client.get::<String, ResponseBodyMock>("/api/v2/get".to_string()).unwrap();

		assert_eq!(get_response.method.as_str(), "GET");
		assert_eq!(get_response.path.as_str(), "/api/v2/get");
	}

	#[test]
	pub fn get_with_query_parameters_works() {
		let mut rest_client = create_default_rest_client();

		let get_response = rest_client
			.get_with::<String, ResponseBodyMock>(
				"/api/v1/get".to_string(),
				&[("order", "desc"), ("user", "spongebob")],
			)
			.unwrap();

		assert_eq!(2, get_response.query_parameters.len());
	}

	fn create_default_rest_client() -> RestClient<HttpClientMock> {
		let base_url = Url::parse("https://example.com").unwrap();
		let http_client = HttpClientMock::new(None);
		RestClient::new(http_client, base_url)
	}
}
