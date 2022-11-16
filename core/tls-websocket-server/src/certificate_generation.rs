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

use crate::{error::WebSocketError, WebSocketResult};
use bit_vec::BitVec;
use chrono::{prelude::*, TimeZone, Utc as TzUtc};
use core::convert::TryFrom;
use rcgen::{date_time_ymd, Certificate, CertificateParams, DistinguishedName, DnType};
use sp_core::{crypto::Pair, ed25519};
use std::{
	string::ToString,
	time::{SystemTime, UNIX_EPOCH},
	vec,
	vec::Vec,
};
use yasna::models::ObjectIdentifier;

const ED25519: &[u64] = &[1, 3, 101, 112];

/// Create a sel-signed certificate, signed with the Ed25519 private key
/// Certificate Params are :
/// - alg: &PKCS_ED25519 -> ED25519 curve signing as per [RFC 8410](https://tools.ietf.org/html/rfc8410)
/// - common_name : the “subject”of the certificate, which is the identity of the certificate/website owner.
/// - not_before : now
/// - not_after : 4096-01-01 -> Certificate valid from initialisation time until 4096-01-01
/// - serial_number : None,
/// - subject_alt_names : common_name. Required parameter. See below, subject
/// - DistinguishedName :
///         - issuer : Integritee, (The issuer field identifies the entity that has signed and issued the certificate.  
///                 The issuer field MUST contain a non-empty distinguished name (DN) )
///         - subject: empty. (The subject field identifies the entity associated with the public key stored in the subject
///                 public key field. If subject naming information is present only in the subjectAltName extension
///                 (e.g., a key bound only to an email address or URI), then the subject name MUST be an empty sequence
///                 and the subjectAltName extension MUST be critical.
/// - is_ca : SelfSignedOnly -> The certificate can only sign itself
/// - key_usages: empty (The key usage extension defines the purpose (e.g., encipherment, signature, certificate signing) of
///                 the key contained in the certificate.  The usage restriction might be employed when a key that could
///                 be used for more than one operation is to be restricted.)
/// - extended_key_usages: empty ( This extension indicates one or more purposes for which the certified public key may be used,
///                in addition to or in place of the basic purposes indicated in the key usage extension.)
/// - name_constraints : None (only relevant for CA certificates)
/// - custom_extensions: None (The extensions defined for X.509 v3 certificates provide methods for associating additional
///                 attributes with users or public keys and for  managing relationships between CAs.)
/// - key_pair : rcgen::KeyPair from enclave private key. (A key pair used to sign certificates and CSRs)
/// - use_authority_key_identifier_extension: false (If `true` (and not self-signed), the 'Authority Key Identifier' extension will be added to the generated cert)
/// - key_identifier_method : KeyIdMethod::Sha256 (Method to generate key identifiers from public keys)

pub fn ed25519_self_signed_certificate(
	key_pair: ed25519::Pair,
	common_name: &str,
) -> WebSocketResult<Certificate> {
	let mut params = CertificateParams::new(vec![common_name.to_string()]);
	let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Error: UNIX_EPOCH");
	let issue_ts = TzUtc
		.timestamp_opt(now.as_secs() as i64, 0)
		.single()
		.expect("Error: this should not fail as long as secs fit into i64");
	let year = issue_ts.year();
	let month = issue_ts.month();
	let day = issue_ts.day();
	params.not_before = date_time_ymd(year, month, day);
	params.not_after = date_time_ymd(4096, 1, 1);
	let mut dn = DistinguishedName::new();
	dn.push(DnType::OrganizationName, "Integritee");
	//dn.push(DnType::CommonName, common_name);
	params.distinguished_name = dn;

	params.alg = &rcgen::PKCS_ED25519; //Signature Algorithm:

	let private_key_der = ed25519_private_key_pkcs8_der(key_pair)?;

	let key_pair = rcgen::KeyPair::try_from(private_key_der.as_ref()).expect("Invalid pkcs8 der");
	params.key_pair = Some(key_pair);

	Certificate::from_params(params).map_err(|e| WebSocketError::Other(e.into()))
}

/// Generate the private key in a PKCS#8 format. To be compatible with rcgen lib.
///  PKCS#8 is specified in [RFC 5958].
///
/// [RFC 5958]: https://tools.ietf.org/html/rfc5958.
fn ed25519_private_key_pkcs8_der(key_pair: ed25519::Pair) -> WebSocketResult<Vec<u8>> {
	let seed = key_pair.seed();
	let private_key = seed.as_slice();
	let pk = key_pair.public().0;
	let public_key = pk.as_slice();
	let key_der = yasna::construct_der(|writer| {
		writer.write_sequence(|writer| {
			writer.next().write_u8(1);
			// write OID
			writer.next().write_sequence(|writer| {
				writer.next().write_oid(&ObjectIdentifier::from_slice(ED25519));
			});
			let pk = yasna::construct_der(|writer| writer.write_bytes(private_key));
			writer.next().write_bytes(&pk);
			writer.next().write_tagged(yasna::Tag::context(1), |writer| {
				writer.write_bitvec(&BitVec::from_bytes(public_key))
			})
		});
	});
	Ok(key_der)
}

#[cfg(test)]
mod tests {
	use crate::certificate_generation::ed25519_self_signed_certificate;
	use sp_core::{crypto::Pair, ed25519};
	use std::time::SystemTime;
	use webpki::TLSServerTrustAnchors;

	type Seed = [u8; 32];
	const TEST_SEED: Seed = *b"12345678901234567890123456789012";

	#[test]
	pub fn test_verify_signature_self_signed_certificate() {
		let signing = signer();
		let pk = signing.public().0;
		let public_key = pk.as_slice();
		let cert = ed25519_self_signed_certificate(signing, "Test").unwrap();
		let sign_pub_key = cert.get_key_pair().public_key_raw();
		assert_eq!(public_key, sign_pub_key);
	}

	#[test]
	pub fn test_verify_is_valid_tls_server_certificate() {
		let common_name = "Test";
		let signing = signer();
		let cert = ed25519_self_signed_certificate(signing, common_name).unwrap();

		//write certificate and private key pem file
		//let cert_der = cert.serialize_der().unwrap();
		//fs::write("test_cert.der", &cert_der).unwrap();

		let cert_der = cert.serialize_der().unwrap();
		let end_entity_cert = webpki::EndEntityCert::from(&cert_der).unwrap();

		let time = webpki::Time::try_from(SystemTime::now());

		let trust_anchor = webpki::trust_anchor_util::cert_der_as_trust_anchor(&cert_der).unwrap();
		let trust_anchor_list = &[trust_anchor];
		let trust_anchors = TLSServerTrustAnchors(trust_anchor_list);

		assert!(end_entity_cert
			.verify_is_valid_tls_server_cert(
				&[&webpki::ED25519],
				&trust_anchors,
				&[],
				time.unwrap(),
			)
			.is_ok());
	}

	fn signer() -> ed25519::Pair {
		ed25519::Pair::from_seed(&TEST_SEED)
	}
}
