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

use crate::{
	error::Error,
	http_client::{EncodedBody, SendHttpRequest},
	Query, RestPath,
};
use http_req::{request::Method, response::Response};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_HEAD: &[u8; 102] = b"HTTP/1.1 200 OK\r\n\
                         		Date: Sat, 11 Jan 2003 02:44:04 GMT\r\n\
                        		Content-Type: text/html\r\n\
                        		Content-Length: 100\r\n\r\n";

/// Response body returned by the HTTP client mock, contains information passed in by caller
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ResponseBodyMock {
	pub base_url: String,
	pub method: String,
	pub path: String,
	pub request_body: Option<String>,
	pub query_parameters: Vec<(String, String)>,
}

impl RestPath<String> for ResponseBodyMock {
	fn get_path(path: String) -> Result<String, Error> {
		Ok(format!("{}", path))
	}
}

/// HTTP client mock - to be used in unit tests
pub struct HttpClientMock {
	response: Option<Response>,
}

impl HttpClientMock {
	pub fn new(response: Option<Response>) -> Self {
		HttpClientMock { response }
	}
}

impl SendHttpRequest for HttpClientMock {
	fn send_request<U, T>(
		&self,
		base_url: Url,
		method: Method,
		params: U,
		query: Option<&Query<'_>>,
		maybe_body: Option<String>,
	) -> Result<(Response, EncodedBody), Error>
	where
		T: RestPath<U>,
	{
		let path = T::get_path(params)?;
		let response = self
			.response
			.clone()
			.unwrap_or_else(|| Response::from_head(DEFAULT_HEAD).unwrap());
		let base_url_str = String::from(base_url.as_str());

		let query_parameters = query
			.map(|q| q.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect())
			.unwrap_or_else(|| Vec::<(String, String)>::new());

		let response_body = ResponseBodyMock {
			base_url: base_url_str,
			method: format!("{:?}", method),
			path,
			request_body: maybe_body,
			query_parameters,
		};

		let encoded_response_body = serde_json::to_vec(&response_body).unwrap();

		Ok((response, encoded_response_body))
	}
}

#[cfg(test)]
mod tests {

	use super::*;

	#[test]
	pub fn response_body_mock_serialization_works() {
		let response_body_mock = ResponseBodyMock {
			base_url: "https://mydomain.com".to_string(),
			method: "GET".to_string(),
			path: "/api/v1".to_string(),
			request_body: None,
			query_parameters: vec![("order".to_string(), "desc".to_string())],
		};

		let serialized_body = serde_json::to_string(&response_body_mock).unwrap();
		let deserialized_body: ResponseBodyMock =
			serde_json::from_str(serialized_body.as_str()).unwrap();

		assert_eq!(deserialized_body, response_body_mock);
	}

	#[test]
	pub fn default_head_is_valid() {
		assert!(Response::from_head(DEFAULT_HEAD).is_ok());
	}

	#[test]
	pub fn client_mock_returns_parameters_in_result() {
		let client_mock = HttpClientMock::new(None);
		let base_url = Url::parse("https://integritee.network").unwrap();

		let (response, encoded_response_body) = client_mock
			.send_request::<String, ResponseBodyMock>(
				base_url,
				Method::GET,
				"/api/v1/get".to_string(),
				None,
				None,
			)
			.unwrap();

		let response_body: ResponseBodyMock =
			serde_json::from_slice(encoded_response_body.as_slice()).unwrap();

		assert_eq!(response, Response::from_head(DEFAULT_HEAD).unwrap());
		assert_eq!(response_body.method.as_str(), "GET");
	}
}
