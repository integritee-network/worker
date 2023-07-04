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

use crate::{error::Error, Query, RestPath};
use http::{
	header::{HeaderName, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
	HeaderValue,
};
use http_req::{
	request::{Method, Request},
	response::{Headers, Response},
	tls::Config,
	uri::Uri,
};
use log::*;
use std::{
	collections::HashMap,
	convert::TryFrom,
	str::FromStr,
	string::{String, ToString},
	time::Duration,
	vec::Vec,
};
use url::Url;

pub type EncodedBody = Vec<u8>;

/// Simple trait to send HTTP request
pub trait SendHttpRequest {
	fn send_request<U, T>(
		&self,
		base_url: Url,
		method: Method,
		params: U,
		query: Option<&Query<'_>>,
		maybe_body: Option<String>,
	) -> Result<(Response, EncodedBody), Error>
	where
		T: RestPath<U>;
}

/// Send trait used by the http client to send HTTP request, based on `http_req`.
pub trait Send {
	fn execute_send_request(
		&self,
		request: &mut Request,
		writer: &mut Vec<u8>,
	) -> Result<Response, Error>;
}

/// HTTP client implementation
///
/// wrapper for the `http_req` library that adds the necessary headers and body to a request
pub struct HttpClient<SendType> {
	send: SendType,
	send_null_body: bool,
	timeout: Option<Duration>,
	headers: Headers,
	authorization: Option<String>,
}

/// Default send method.
/// Automatically upgrades to TLS in case the base URL contains 'https'
/// For https requests, the default trusted server's certificates
/// are provided by the default tls configuration of the http_req lib
pub struct DefaultSend;

impl Send for DefaultSend {
	fn execute_send_request(
		&self,
		request: &mut Request,
		writer: &mut Vec<u8>,
	) -> Result<Response, Error> {
		request.send(writer).map_err(Error::HttpReqError)
	}
}

/// Sends a HTTPs request with the server's root certificate(s).
/// The connection will only be established if one of the supplied certificates
/// matches the server's root certificate.
pub struct SendWithCertificateVerification {
	root_certificates: Vec<String>,
}

impl SendWithCertificateVerification {
	pub fn new(root_certificates: Vec<String>) -> Self {
		SendWithCertificateVerification { root_certificates }
	}
}

impl Send for SendWithCertificateVerification {
	fn execute_send_request(
		&self,
		request: &mut Request,
		writer: &mut Vec<u8>,
	) -> Result<Response, Error> {
		let mut cnf = Config::empty_root_store();
		for cert in self.root_certificates.iter() {
			cnf.add_root_cert_content_pem_file(cert)?;
		}

		match request.send_with_config(writer, Some(&cnf)) {
			Ok(response) => Ok(response),
			Err(e) => {
				error!(
					"SendWithCertificateVerification::execute_send_request received error: {:#?}",
					&e
				);
				Err(Error::HttpReqError(e))
			},
		}
	}
}

impl<SendType> HttpClient<SendType>
where
	SendType: Send,
{
	pub fn new(
		send: SendType,
		send_null_body: bool,
		timeout: Option<Duration>,
		headers: Option<Headers>,
		authorization: Option<String>,
	) -> Self {
		HttpClient {
			send,
			send_null_body,
			timeout,
			headers: headers.unwrap_or_else(Headers::new),
			authorization,
		}
	}

	/// Set credentials for HTTP Basic authentication.
	pub fn set_auth(&mut self, user: &str, pass: &str) {
		let mut s: String = user.to_string();
		s.push(':');
		s.push_str(pass);
		self.authorization = Some(format!("Basic {}", base64::encode(&s)));
	}

	/// Set HTTP header from string name and value.
	///
	/// The header is added to all subsequent GET and POST requests
	/// unless the headers are cleared with `clear_headers()` call.
	pub fn set_header(&mut self, name: &'static str, value: &str) -> Result<(), Error> {
		let header_name = HeaderName::from_str(name).map_err(|_| Error::InvalidValue)?;
		let value = HeaderValue::from_str(value).map_err(|_| Error::InvalidValue)?;

		add_to_headers(&mut self.headers, header_name, value);
		Ok(())
	}

	/// Clear all previously set headers
	pub fn clear_headers(&mut self) {
		self.headers = Headers::new();
	}
}

impl<SendType> SendHttpRequest for HttpClient<SendType>
where
	SendType: Send,
{
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
		let url = join_url(base_url, T::get_path(params)?.as_str(), query)?;
		let uri = Uri::try_from(url.as_str()).map_err(Error::HttpReqError)?;

		trace!("uri: {:?}", uri);

		let mut request = Request::new(&uri);
		request.method(method);

		let mut request_headers = Headers::default_http(&uri);

		if let Some(body) = maybe_body.as_ref() {
			if self.send_null_body || body != "null" {
				let len = HeaderValue::from_str(&body.len().to_string())
					.map_err(|_| Error::RequestError)?;

				add_to_headers(&mut request_headers, CONTENT_LENGTH, len);
				add_to_headers(
					&mut request_headers,
					CONTENT_TYPE,
					HeaderValue::from_str("application/json")
						.expect("Request Header: invalid characters"),
				);

				trace!("set request body: {}", body);
				request.body(body.as_bytes()); // takes body non-owned (!)
			}
		} else {
			debug!("no body to send");
		}

		if let Some(ref auth) = self.authorization {
			add_to_headers(
				&mut request_headers,
				AUTHORIZATION,
				HeaderValue::from_str(auth).map_err(|_| Error::RequestError)?,
			);
		}

		// add pre-set headers
		for (key, value) in self.headers.iter() {
			request_headers.insert(key, &value.clone());
		}

		// add user agent header
		let pkg_version = env!("CARGO_PKG_VERSION");
		add_to_headers(
			&mut request_headers,
			USER_AGENT,
			HeaderValue::from_str(format!("integritee/{}", pkg_version).as_str())
				.map_err(|_| Error::RequestError)?,
		);

		request.headers(HashMap::from(request_headers));

		request
			.timeout(self.timeout)
			.connect_timeout(self.timeout)
			.read_timeout(self.timeout)
			.write_timeout(self.timeout);

		trace!("request is: {:?}", request);

		let mut writer = Vec::new();

		let response = self.send.execute_send_request(&mut request, &mut writer)?;

		Ok((response, writer))
	}
}

fn join_url(base_url: Url, path: &str, params: Option<&Query>) -> Result<Url, Error> {
	let mut url = base_url.join(path).map_err(|_| Error::UrlError)?;

	if let Some(params) = params {
		for &(key, item) in params.iter() {
			url.query_pairs_mut().append_pair(key, item);
		}
	}

	Ok(url)
}

fn add_to_headers(headers: &mut Headers, key: HeaderName, value: HeaderValue) {
	let header_value_str = value.to_str();

	match header_value_str {
		Ok(v) => {
			headers.insert(key.as_str(), v);
		},
		Err(e) => {
			error!("Failed to add header to request: {:?}", e);
		},
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use core::assert_matches::assert_matches;
	use http::header::CONNECTION;
	use serde::{Deserialize, Serialize};
	use std::vec::Vec;

	const HTTPBIN_ROOT_CERT: &str = include_str!("fixtures/amazon_root_ca_1_v3.pem");
	const COINGECKO_ROOT_CERTIFICATE_BALTIMORE: &str =
		include_str!("fixtures/baltimore_cyber_trust_root_v3.pem");
	const COINGECKO_ROOT_CERTIFICATE_LETSENCRYPT: &str =
		include_str!("fixtures/lets_encrypt_root_cert.pem");

	#[test]
	fn join_url_adds_query_parameters() {
		let base_url = Url::parse("https://example.com").unwrap();
		let path = "api/v2/example_list";
		let query = [("filter", "all"), ("order", ("desc"))];

		let complete_url = join_url(base_url, path, Some(&query)).unwrap();

		assert_eq!(
			complete_url.as_str(),
			"https://example.com/api/v2/example_list?filter=all&order=desc"
		);
	}

	#[test]
	fn join_url_has_no_query_parameters() {
		let base_url = Url::parse("https://example.com").unwrap();
		let path = "api/v2/endpoint";
		let complete_url = join_url(base_url, path, None).unwrap();
		assert_eq!(complete_url.as_str(), "https://example.com/api/v2/endpoint");
	}

	#[test]
	fn join_url_with_too_many_slashes() {
		let base_url = Url::parse("https://api.mydomain.com").unwrap();
		let path = "/api/v1/post";
		let complete_url = join_url(base_url, path, None).unwrap();
		assert_eq!(complete_url.as_str(), "https://api.mydomain.com/api/v1/post");
	}

	#[test]
	#[ignore = "depends on external web-service that proved to be unreliable for CI"]
	fn get_with_parameters() {
		#[derive(Serialize, Deserialize, Debug)]
		struct RequestArgs {
			pub order: String,
			pub filter: String,
		}

		// Data structure that matches with REST API JSON
		#[derive(Serialize, Deserialize, Debug)]
		struct HttpBinAnything {
			pub args: RequestArgs,
			pub origin: String,
			pub url: String,
		}

		impl RestPath<()> for HttpBinAnything {
			fn get_path(_: ()) -> Result<String, Error> {
				Ok(format!("anything"))
			}
		}

		let http_client = HttpClient::new(
			DefaultSend {},
			true,
			Some(Duration::from_secs(3u64)),
			Some(headers_connection_close()),
			None,
		);
		let base_url = Url::parse("https://httpbin.org").unwrap();
		let query_parameters = [("order", "desc"), ("filter", "all")];

		let (response, encoded_body) = http_client
			.send_request::<(), HttpBinAnything>(
				base_url,
				Method::GET,
				(),
				Some(&query_parameters),
				None,
			)
			.unwrap();

		let response_body: HttpBinAnything =
			deserialize_response_body(encoded_body.as_slice()).unwrap();

		assert!(response.status_code().is_success());
		assert_eq!(response_body.args.order.as_str(), "desc");
		assert_eq!(response_body.args.filter.as_str(), "all");
	}

	#[test]
	#[ignore = "depends on external web-service that proved to be unreliable for CI"]
	fn get_without_parameters() {
		// Data structure that matches with REST API JSON
		#[derive(Serialize, Deserialize, Debug)]
		struct HttpBinAnything {
			pub method: String,
			pub url: String,
		}

		impl RestPath<()> for HttpBinAnything {
			fn get_path(_: ()) -> Result<String, Error> {
				Ok(format!("anything"))
			}
		}

		let http_client = HttpClient::new(
			DefaultSend {},
			true,
			Some(Duration::from_secs(3u64)),
			Some(headers_connection_close()),
			None,
		);
		let base_url = Url::parse("https://httpbin.org").unwrap();

		let (response, encoded_body) = http_client
			.send_request::<(), HttpBinAnything>(base_url, Method::GET, (), None, None)
			.unwrap();

		let response_body: HttpBinAnything =
			deserialize_response_body(encoded_body.as_slice()).unwrap();

		assert!(response.status_code().is_success());
		assert!(!response_body.url.is_empty());
		assert_eq!(response_body.method.as_str(), "GET");
	}

	#[test]
	#[ignore = "depends on external web-service that proved to be unreliable for CI"]
	fn post_with_body() {
		#[derive(Serialize, Deserialize, Debug)]
		struct HttpBinAnything {
			pub data: String,
			pub method: String,
		}

		impl RestPath<()> for HttpBinAnything {
			fn get_path(_: ()) -> Result<String, Error> {
				Ok(format!("anything"))
			}
		}

		let http_client = HttpClient::new(
			DefaultSend {},
			false,
			Some(Duration::from_secs(3u64)),
			Some(headers_connection_close()),
			None,
		);

		let body_test = "this is a test body with special characters {::}/-".to_string();
		let base_url = Url::parse("https://httpbin.org").unwrap();

		let (response, encoded_body) = http_client
			.send_request::<(), HttpBinAnything>(
				base_url,
				Method::POST,
				(),
				None,
				Some(body_test.clone()),
			)
			.unwrap();

		let response_body: HttpBinAnything =
			deserialize_response_body(encoded_body.as_slice()).unwrap();

		assert!(response.status_code().is_success());
		assert_eq!(response_body.method.as_str(), "POST");
		assert_eq!(response_body.data, body_test);
	}

	#[test]
	#[ignore = "depends on external web-service that proved to be unreliable for CI"]
	fn get_coins_list_from_coin_gecko_works() {
		// Data structure that matches with REST API JSON
		#[derive(Serialize, Deserialize, Debug)]
		struct CoinGeckoCoinsList {
			id: String,
			symbol: String,
			name: String,
		}

		impl RestPath<()> for Vec<CoinGeckoCoinsList> {
			fn get_path(_: ()) -> Result<String, Error> {
				Ok(format!("api/v3/coins/list"))
			}
		}

		let http_client =
			HttpClient::new(DefaultSend {}, true, Some(Duration::from_secs(3u64)), None, None);
		let base_url = Url::parse("https://api.coingecko.com").unwrap();

		let (response, encoded_body) = http_client
			.send_request::<(), Vec<CoinGeckoCoinsList>>(base_url, Method::GET, (), None, None)
			.unwrap();

		let coins_list: Vec<CoinGeckoCoinsList> =
			deserialize_response_body(encoded_body.as_slice()).unwrap();

		assert!(response.status_code().is_success());
		assert!(!coins_list.is_empty());
	}

	#[test]
	#[ignore = "depends on external web-service that proved to be unreliable for CI"]
	fn authenticated_get_works() {
		#[derive(Serialize, Deserialize, Debug)]
		struct HttpBinAnything {
			pub method: String,
			pub url: String,
		}

		impl RestPath<()> for HttpBinAnything {
			fn get_path(_: ()) -> Result<String, Error> {
				Ok(format!("anything"))
			}
		}
		let base_url = Url::parse("https://httpbin.org").unwrap();
		let root_certificate = HTTPBIN_ROOT_CERT.to_string();

		let http_client = HttpClient::new(
			SendWithCertificateVerification::new(vec![root_certificate]),
			true,
			Some(Duration::from_secs(3u64)),
			Some(headers_connection_close()),
			None,
		);

		let (response, encoded_body) = http_client
			.send_request::<(), HttpBinAnything>(base_url, Method::GET, (), None, None)
			.unwrap();

		let response_body: HttpBinAnything =
			deserialize_response_body(encoded_body.as_slice()).unwrap();

		assert!(response.status_code().is_success());
		assert!(!response_body.url.is_empty());
		assert_eq!(response_body.method.as_str(), "GET");
	}

	#[test]
	#[ignore = "depends on external web-service that proved to be unreliable for CI"]
	fn authenticated_get_with_wrong_root_certificate_fails() {
		#[derive(Serialize, Deserialize, Debug)]
		struct HttpBinAnything {
			pub method: String,
			pub url: String,
		}

		impl RestPath<()> for HttpBinAnything {
			fn get_path(_: ()) -> Result<String, Error> {
				Ok(format!("anything"))
			}
		}

		let base_url = Url::parse("https://httpbin.org").unwrap();
		let root_certificates = vec![
			COINGECKO_ROOT_CERTIFICATE_LETSENCRYPT.to_string(),
			COINGECKO_ROOT_CERTIFICATE_BALTIMORE.to_string(),
		];

		let http_client = HttpClient::new(
			SendWithCertificateVerification::new(root_certificates),
			true,
			Some(Duration::from_secs(3u64)),
			Some(headers_connection_close()),
			None,
		);

		let result =
			http_client.send_request::<(), HttpBinAnything>(base_url, Method::GET, (), None, None);
		assert_matches!(result, Err(Error::HttpReqError(_)));
		let msg = format!("error {:?}", result.err());
		assert!(msg.contains("UnknownIssuer"));
	}

	fn headers_connection_close() -> Headers {
		let mut headers = Headers::new();
		add_to_headers(&mut headers, CONNECTION, HeaderValue::from_str("close").unwrap());
		headers
	}

	fn deserialize_response_body<'a, T>(encoded_body: &'a [u8]) -> Result<T, Error>
	where
		T: Deserialize<'a>,
	{
		serde_json::from_slice::<'a, T>(encoded_body).map_err(|err| {
			Error::DeserializeParseError(err, String::from_utf8_lossy(encoded_body).to_string())
		})
	}
}
