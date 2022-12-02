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

use crate::{Error as EnclaveError, Result as EnclaveResult};
use arrayvec::ArrayVec;
use chrono::DateTime;
use itertools::Itertools;
use itp_ocall_api::EnclaveAttestationOCallApi;
use log::*;
use serde_json::Value;
use sgx_types::{
	sgx_platform_info_t, sgx_quote_t, sgx_status_t, SgxResult, SGX_PLATFORM_INFO_SIZE,
};
use std::{
	io::BufReader,
	ptr, str,
	string::String,
	time::{SystemTime, UNIX_EPOCH},
	vec::Vec,
};

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
	&webpki::ECDSA_P256_SHA256,
	&webpki::ECDSA_P256_SHA384,
	&webpki::ECDSA_P384_SHA256,
	&webpki::ECDSA_P384_SHA384,
	&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
	&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
	&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
	&webpki::RSA_PKCS1_2048_8192_SHA256,
	&webpki::RSA_PKCS1_2048_8192_SHA384,
	&webpki::RSA_PKCS1_2048_8192_SHA512,
	&webpki::RSA_PKCS1_3072_8192_SHA384,
];

pub const CERTEXPIRYDAYS: i64 = 90i64;
pub const IAS_REPORT_CA: &[u8] = include_bytes!("../AttestationReportSigningCACert.pem");

#[cfg(feature = "sgx")]
pub use sgx::*;

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::*;
	use bit_vec::BitVec;
	use chrono::{Duration, TimeZone, Utc as TzUtc};
	use num_bigint::BigUint;
	use sgx_tcrypto::SgxEccHandle;
	use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t};
	use yasna::models::ObjectIdentifier;

	const ISSUER: &str = "Integritee";
	const SUBJECT: &str = "Integritee ephemeral";

	pub fn gen_ecc_cert(
		payload: &[u8],
		prv_k: &sgx_ec256_private_t,
		pub_k: &sgx_ec256_public_t,
		ecc_handle: &SgxEccHandle,
	) -> Result<(Vec<u8>, Vec<u8>), sgx_status_t> {
		// Generate public key bytes since both DER will use it
		let mut pub_key_bytes: Vec<u8> = vec![4];
		let mut pk_gx = pub_k.gx;
		pk_gx.reverse();
		let mut pk_gy = pub_k.gy;
		pk_gy.reverse();
		pub_key_bytes.extend_from_slice(&pk_gx);
		pub_key_bytes.extend_from_slice(&pk_gy);

		// Generate Certificate DER
		let cert_der = yasna::construct_der(|writer| {
			writer.write_sequence(|writer| {
				writer.next().write_sequence(|writer| {
					// Certificate Version
					writer.next().write_tagged(yasna::Tag::context(0), |writer| {
						writer.write_i8(2);
					});
					// Certificate Serial Number (unused but required)
					writer.next().write_u8(1);
					// Signature Algorithm: ecdsa-with-SHA256
					writer.next().write_sequence(|writer| {
						writer
							.next()
							.write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
					});
					// Issuer: CN=MesaTEE (unused but required)
					writer.next().write_sequence(|writer| {
						writer.next().write_set(|writer| {
							writer.next().write_sequence(|writer| {
								writer
									.next()
									.write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
								writer.next().write_utf8_string(ISSUER);
							});
						});
					});
					// Validity: Issuing/Expiring Time (unused but required)
					let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
					let issue_ts = TzUtc.timestamp(now.as_secs() as i64, 0);
					let expire = now + Duration::days(CERTEXPIRYDAYS).to_std().unwrap();
					let expire_ts = TzUtc.timestamp(expire.as_secs() as i64, 0);
					writer.next().write_sequence(|writer| {
						writer
							.next()
							.write_utctime(&yasna::models::UTCTime::from_datetime(&issue_ts));
						writer
							.next()
							.write_utctime(&yasna::models::UTCTime::from_datetime(&expire_ts));
					});
					// Subject: CN=MesaTEE (unused but required)
					writer.next().write_sequence(|writer| {
						writer.next().write_set(|writer| {
							writer.next().write_sequence(|writer| {
								writer
									.next()
									.write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
								writer.next().write_utf8_string(SUBJECT);
							});
						});
					});
					writer.next().write_sequence(|writer| {
						// Public Key Algorithm
						writer.next().write_sequence(|writer| {
							// id-ecPublicKey
							writer.next().write_oid(&ObjectIdentifier::from_slice(&[
								1, 2, 840, 10045, 2, 1,
							]));
							// prime256v1
							writer.next().write_oid(&ObjectIdentifier::from_slice(&[
								1, 2, 840, 10045, 3, 1, 7,
							]));
						});
						// Public Key
						writer.next().write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
					});
					// Certificate V3 Extension
					writer.next().write_tagged(yasna::Tag::context(3), |writer| {
						writer.write_sequence(|writer| {
							writer.next().write_sequence(|writer| {
								writer.next().write_oid(&ObjectIdentifier::from_slice(&[
									2, 16, 840, 1, 113_730, 1, 13,
								]));
								writer.next().write_bytes(payload);
							});
						});
					});
				});
				// Signature Algorithm: ecdsa-with-SHA256
				writer.next().write_sequence(|writer| {
					writer
						.next()
						.write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
				});
				// Signature
				let sig = {
					let tbs = &writer.buf[4..];
					ecc_handle.ecdsa_sign_slice(tbs, prv_k).unwrap()
				};
				let sig_der = yasna::construct_der(|writer| {
					writer.write_sequence(|writer| {
						let mut sig_x = sig.x;
						sig_x.reverse();
						let mut sig_y = sig.y;
						sig_y.reverse();
						writer.next().write_biguint(&BigUint::from_slice(&sig_x));
						writer.next().write_biguint(&BigUint::from_slice(&sig_y));
					});
				});
				writer.next().write_bitvec(&BitVec::from_bytes(&sig_der));
			});
		});

		// Generate Private Key DER
		let key_der = yasna::construct_der(|writer| {
			writer.write_sequence(|writer| {
				writer.next().write_u8(0);
				writer.next().write_sequence(|writer| {
					writer
						.next()
						.write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
					writer
						.next()
						.write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
				});
				let inner_key_der = yasna::construct_der(|writer| {
					writer.write_sequence(|writer| {
						writer.next().write_u8(1);
						let mut prv_k_r = prv_k.r;
						prv_k_r.reverse();
						writer.next().write_bytes(&prv_k_r);
						writer.next().write_tagged(yasna::Tag::context(1), |writer| {
							writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
						});
					});
				});
				writer.next().write_bytes(&inner_key_der);
			});
		});

		Ok((key_der, cert_der))
	}
}

pub fn percent_decode(orig: String) -> EnclaveResult<String> {
	let v: Vec<&str> = orig.split('%').collect();
	let mut ret = String::new();
	ret.push_str(v[0]);
	if v.len() > 1 {
		for s in v[1..].iter() {
			ret.push(u8::from_str_radix(&s[0..2], 16).map_err(|e| EnclaveError::Other(e.into()))?
				as char);
			ret.push_str(&s[2..]);
		}
	}
	Ok(ret)
}

// FIXME: This code is redundant with the host call of the integritee-node
pub fn verify_mra_cert<A>(cert_der: &[u8], attestation_ocall: &A) -> SgxResult<()>
where
	A: EnclaveAttestationOCallApi,
{
	// Before we reach here, Webpki already verified the cert is properly signed

	// Search for Public Key prime256v1 OID
	let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
	let mut offset = cert_der
		.windows(prime256v1_oid.len())
		.position(|window| window == prime256v1_oid)
		.ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;
	offset += 11; // 10 + TAG (0x03)

	// Obtain Public Key length
	let mut len = cert_der[offset] as usize;
	if len > 0x80 {
		len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
		offset += 2;
	}

	// Obtain Public Key
	offset += 1;
	let pub_k = cert_der[offset + 2..offset + len].to_vec(); // skip "00 04"

	// Search for Netscape Comment OID
	let ns_cmt_oid = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D];
	let mut offset = cert_der
		.windows(ns_cmt_oid.len())
		.position(|window| window == ns_cmt_oid)
		.ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;
	offset += 12; // 11 + TAG (0x04)

	// Obtain Netscape Comment length
	let mut len = cert_der[offset] as usize;
	if len > 0x80 {
		len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
		offset += 2;
	}

	// Obtain Netscape Comment
	offset += 1;
	let payload = cert_der[offset..offset + len].to_vec();

	// Extract each field
	let mut iter = payload.split(|x| *x == 0x7C);
	let attn_report_raw = iter.next().ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;
	let sig_raw = iter.next().ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;
	let sig = base64::decode(sig_raw).map_err(|e| EnclaveError::Other(e.into()))?;

	let sig_cert_raw = iter.next().ok_or(sgx_status_t::SGX_ERROR_UNEXPECTED)?;
	let sig_cert_dec = base64::decode_config(sig_cert_raw, base64::STANDARD)
		.map_err(|e| EnclaveError::Other(e.into()))?;
	let sig_cert = webpki::EndEntityCert::from(&sig_cert_dec).expect("Bad DER");

	// Verify if the signing cert is issued by Intel CA
	let mut ias_ca_stripped = IAS_REPORT_CA.to_vec();
	ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
	let head_len = "-----BEGIN CERTIFICATE-----".len();
	let tail_len = "-----END CERTIFICATE-----".len();
	let full_len = ias_ca_stripped.len();
	let ias_ca_core: &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
	let ias_cert_dec = base64::decode_config(ias_ca_core, base64::STANDARD)
		.map_err(|e| EnclaveError::Other(e.into()))?;

	let mut ca_reader = BufReader::new(IAS_REPORT_CA);

	let mut root_store = rustls::RootCertStore::empty();
	root_store.add_pem_file(&mut ca_reader).expect("Failed to add CA");

	let trust_anchors: Vec<webpki::TrustAnchor> =
		root_store.roots.iter().map(|cert| cert.to_trust_anchor()).collect();

	let now_func = webpki::Time::try_from(SystemTime::now());

	match sig_cert.verify_is_valid_tls_server_cert(
		SUPPORTED_SIG_ALGS,
		&webpki::TLSServerTrustAnchors(&trust_anchors),
		&[ias_cert_dec.as_slice()],
		now_func.map_err(|_e| EnclaveError::Time)?,
	) {
		Ok(_) => info!("Cert is good"),
		Err(e) => {
			error!("Cert verification error {:?}", e);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		},
	}

	// Verify the signature against the signing cert
	match sig_cert.verify_signature(&webpki::RSA_PKCS1_2048_8192_SHA256, attn_report_raw, &sig) {
		Ok(_) => info!("Signature good"),
		Err(e) => {
			error!("Signature verification error {:?}", e);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		},
	}

	verify_attn_report(attn_report_raw, pub_k, attestation_ocall)
}

pub fn verify_attn_report<A>(
	report_raw: &[u8],
	pub_k: Vec<u8>,
	attestation_ocall: &A,
) -> SgxResult<()>
where
	A: EnclaveAttestationOCallApi,
{
	// Verify attestation report
	// 1. Check timestamp is within 24H (90day is recommended by Intel)
	let attn_report: Value =
		serde_json::from_slice(report_raw).map_err(|e| EnclaveError::Other(e.into()))?;
	if let Value::String(time) = &attn_report["timestamp"] {
		let time_fixed = time.clone() + "+0000";
		let ts = DateTime::parse_from_str(&time_fixed, "%Y-%m-%dT%H:%M:%S%.f%z")
			.map_err(|e| EnclaveError::Other(e.into()))?
			.timestamp();
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|e| EnclaveError::Other(e.into()))?
			.as_secs() as i64;
		info!("Time diff = {}", now - ts);
	} else {
		error!("Failed to fetch timestamp from attestation report");
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	// 2. Verify quote status (mandatory field)
	if let Value::String(quote_status) = &attn_report["isvEnclaveQuoteStatus"] {
		debug!("isvEnclaveQuoteStatus = {}", quote_status);
		match quote_status.as_ref() {
			"OK" => (),
			"GROUP_OUT_OF_DATE" | "GROUP_REVOKED" | "CONFIGURATION_NEEDED" => {
				// Verify platformInfoBlob for further info if status not OK
				if let Value::String(pib) = &attn_report["platformInfoBlob"] {
					let mut buf = ArrayVec::<_, SGX_PLATFORM_INFO_SIZE>::new();

					// the TLV Header (4 bytes/8 hexes) should be skipped
					let n = (pib.len() - 8) / 2;
					for i in 0..n {
						buf.try_push(
							u8::from_str_radix(&pib[(i * 2 + 8)..(i * 2 + 10)], 16)
								.map_err(|e| EnclaveError::Other(e.into()))?,
						)
						.map_err(|e| {
							error!("failed to push element to platform info blob buffer, exceeding buffer size ({})", e);
							sgx_status_t::SGX_ERROR_UNEXPECTED
						})?;
					}

					// ArrayVec .into_inner() requires that all elements are occupied by a value
					// if that's not the case, the following error will occur
					let platform_info = buf.into_inner().map_err(|e| {
						error!("Failed to extract platform info from InfoBlob, result does not contain enough elements (require: {}, found: {})", e.capacity(), e.len());
						sgx_status_t::SGX_ERROR_UNEXPECTED
					})?;

					attestation_ocall.get_update_info(sgx_platform_info_t { platform_info }, 1)?;
				} else {
					error!("Failed to fetch platformInfoBlob from attestation report");
					return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
				}
			},
			status => {
				error!("Unexpected status in attestation report: {}", status);
				return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			},
		}
	} else {
		error!("Failed to fetch isvEnclaveQuoteStatus from attestation report");
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	// 3. Verify quote body
	if let Value::String(quote_raw) = &attn_report["isvEnclaveQuoteBody"] {
		let quote = base64::decode(quote_raw).map_err(|e| EnclaveError::Other(e.into()))?;
		debug!("Quote = {:?}", quote);
		// TODO: lack security check here
		let sgx_quote: sgx_quote_t = unsafe { ptr::read(quote.as_ptr() as *const _) };

		let ti = attestation_ocall.get_mrenclave_of_self()?;
		if sgx_quote.report_body.mr_enclave.m != ti.m {
			error!(
				"mr_enclave is not equal to self {:?} != {:?}",
				sgx_quote.report_body.mr_enclave.m, ti.m
			);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		// ATTENTION
		// DO SECURITY CHECK ON DEMAND
		// DO SECURITY CHECK ON DEMAND
		// DO SECURITY CHECK ON DEMAND

		// Curly braces to copy `unaligned_references` of packed fields into properly aligned temporary:
		// https://github.com/rust-lang/rust/issues/82523
		debug!("sgx quote version = {}", { sgx_quote.version });
		debug!("sgx quote signature type = {}", { sgx_quote.sign_type });
		debug!(
			"sgx quote report_data = {:02x}",
			sgx_quote.report_body.report_data.d.iter().format("")
		);
		debug!(
			"sgx quote mr_enclave = {:02x}",
			sgx_quote.report_body.mr_enclave.m.iter().format("")
		);
		debug!("sgx quote mr_signer = {:02x}", sgx_quote.report_body.mr_signer.m.iter().format(""));
		debug!("Anticipated public key = {:02x}", pub_k.iter().format(""));
		if sgx_quote.report_body.report_data.d.to_vec() == pub_k.to_vec() {
			info!("Mutual RA done!");
		}
	} else {
		error!("Failed to fetch isvEnclaveQuoteBody from attestation report");
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	Ok(())
}
