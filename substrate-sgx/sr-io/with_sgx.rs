// Copyright 2017-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

extern crate sgx_tstd as std;

use std::prelude::v1::String;

use codec::{Decode, Encode};
use primitives::{
    hash::H256,
    offchain::{
        Timestamp, HttpRequestId, HttpRequestStatus, HttpError, StorageKind, OpaqueNetworkState,
    },
    crypto::KeyTypeId, ed25519, sr25519
};

use std::char;

#[allow(unused)]
fn encode_hex_digit(digit: u8) -> char {
    match char::from_digit(u32::from(digit), 16) {
        Some(c) => c,
        _ => panic!(),
    }
}

#[allow(unused)]
fn encode_hex_byte(byte: u8) -> [char; 2] {
    [encode_hex_digit(byte >> 4), encode_hex_digit(byte & 0x0Fu8)]
}

#[allow(unused)]
pub fn encode_hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|byte| encode_hex_byte(*byte).iter().copied().collect())
        .collect();
    strs.join("")
}

use sgx_log::*;
use std::{vec, vec::Vec};

// Reexport here, such that the worker does not need to import other crate.
// Not sure if this is a good Idea though.
pub use sgx_externalities::{with_externalities, SgxExternalities, SgxExternalitiesTrait};

/// Error verifying ECDSA signature
#[derive(Encode, Decode)]
pub enum EcdsaVerifyError {
    /// Incorrect value of R or S
    BadRS,
    /// Incorrect value of V
    BadV,
    /// Invalid signature
    BadSignature,

}

pub mod storage {
    use super::*;
    pub fn get(key: &[u8]) -> Option<Vec<u8>> {
        debug!("storage('{}')", encode_hex(key));
        with_externalities(|ext| ext.get(key).map(|s| {
            debug!("  returning {}", encode_hex(s));
            s.to_vec()
        }))
            .expect("storage cannot be called outside of an Externalities-provided environment.")
    }

    pub fn read(key: &[u8], value_out: &mut [u8], value_offset: usize) -> Option<usize> {
        debug!("read_storage('{}' with offset =  {:?}. value_out.len() is {})", encode_hex(key), value_offset, value_out.len());
        with_externalities(|ext| ext.get(key).map(|value| {
            debug!("  entire stored value: {:?}", value);
            let value = &value[value_offset..];
            debug!("  stored value at offset: {:?}", value);
            let written = std::cmp::min(value.len(), value_out.len());
            value_out[..written].copy_from_slice(&value[..written]);
            debug!("  write back {:?}, return len {}", value_out, value.len());
            value.len()
        })).expect("read_storage cannot be called outside of an Externalities-provided environment.")
    }

    pub fn child_get(storage_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        // TODO: unimplemented
        warn!("storage::child_get() unimplemented");
        Some(vec![0,1,2,3])
    }

    pub fn set(key: &[u8], value: &[u8]) {
        debug!("set_storage('{}', {:x?})", encode_hex(key), value);
        with_externalities(|ext|
            ext.insert(key.to_vec(), value.to_vec())
        );
    }

    pub fn child_read(
        storage_key: &[u8],
        key: &[u8],
        value_out: &mut [u8],
        value_offset: usize,
    ) -> Option<usize> {
        // TODO unimplemented
        warn!("storage::child_read() unimplemented");
        Some(0)
    }

    pub fn child_set(storage_key: &[u8], key: &[u8], value: &[u8]) {
        warn!("storage::child_set() unimplemented");
    }

    pub fn clear(key: &[u8]) {
        warn!("storage::clear() unimplemented");
    }

    pub fn child_clear(storage_key: &[u8], key: &[u8]) {
        warn!("storage::child_clear() unimplemented");
    }

    pub fn child_storage_kill(storage_key: &[u8]) {
        warn!("storage::child_storage_kill() unimplemented");
    }

    pub fn exists(key: &[u8]) -> bool {
        warn!("storage::exists unimplemented");
        false
    }

    pub fn child_exists(storage_key: &[u8], key: &[u8]) -> bool {
        warn!("storage::child_exists() unimplemented");
        false
    }

    pub fn clear_prefix(prefix: &[u8]) {
        warn!("storage::clear_prefix() unimplemented");
    }

    pub fn child_clear_prefix(storage_key: &[u8], prefix: &[u8]) {
        warn!("storage::child_clear_prefix() unimplemented");
    }

    pub fn root() -> [u8; 32] {
        warn!("storage::root() unimplemented");
        [0u8; 32]
    }

    pub fn child_root(storage_key: &[u8]) -> Vec<u8> {
        warn!("storage::child_root() unimplemented");
        vec![0,1,2,3]
    }

    pub fn changes_root(parent_hash: [u8; 32]) -> Option<[u8; 32]> {
        warn!("storage::changes_root() unimplemented");
        Some([0u8; 32])
    }

    pub fn blake2_256_trie_root(_input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
        warn!("storage::blake2_256_trie_root unimplemented");
        H256::default()
    }

    pub fn blake2_256_ordered_trie_root(input: Vec<Vec<u8>>) -> H256 {
        warn!("storage::blake2_256_ordered_trie_root unimplemented");
        H256::default()
    }
}


pub mod hashing {
    use super::*;

    pub fn keccak_256(data: &[u8]) -> [u8; 32] {
        warn!("hashing::keccak256 unimplemented");
        [0u8; 32]
    }

    pub fn blake2_128(data: &[u8]) -> [u8; 16] {
        debug!("blake2_128 of {}", encode_hex(data));
        let hash = primitives::blake2_128(data);
        debug!("  returning hash {}", encode_hex(&hash));
        hash
    }

    pub fn blake2_256(data: &[u8]) -> [u8; 32] {
        debug!("blake2_256 of {}", encode_hex(data));
        let hash = primitives::blake2_256(data);
        debug!("  returning hash {}", encode_hex(&hash));
        hash
    }

    pub fn twox_256(data: &[u8]) -> [u8; 32] {
        debug!("twox_256 of {}", encode_hex(data));
        let hash = primitives::twox_256(data);
        debug!("  returning {}", encode_hex(&hash));
        hash
    }

    pub fn twox_128(data: &[u8]) -> [u8; 16] {
        debug!("twox_128 of {}", encode_hex(data));
        let hash = primitives::twox_128(data);
        debug!("  returning {}", encode_hex(&hash));
        hash
    }

    pub fn twox_64(data: &[u8]) -> [u8; 8] {
        debug!("twox_64 of {}", encode_hex(data));
        let hash = primitives::twox_64(data);
        debug!("  returning {}", encode_hex(&hash));
        hash
    }
}

/// Interfaces for working with crypto related types from within the runtime.
pub mod crypto {
    use super::*;

    pub fn ed25519_public_keys(id: KeyTypeId) -> Vec<ed25519::Public> {
        warn!("crypto::ed25519_public_keys unimplemented");
        vec!(ed25519::Public::default())
    }

    pub fn ed25519_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> ed25519::Public {
        warn!("crypto::ed25519_generate unimplemented");
        ed25519::Public::default()
    }

    pub fn ed25519_sign(
        id: KeyTypeId,
        pubkey: &ed25519::Public,
        msg: &[u8],
    ) -> Option<ed25519::Signature> {
        warn!("crypto::ed25519_sign unimplemented");
        Some(ed25519::Signature::default())
    }

    pub fn ed25519_verify(sig: &ed25519::Signature, msg: &[u8], pubkey: &ed25519::Public) -> bool {
        warn!("crypto::ed25519_verify unimplemented");
        true
    }

    pub fn sr25519_public_keys(id: KeyTypeId) -> Vec<sr25519::Public> {
        warn!("crypto::sr25519_public_key unimplemented");
        vec!(sr25519::Public::default())
    }

    pub fn sr25519_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> sr25519::Public {
        warn!("crypto::sr25519_generate unimplemented");
        sr25519::Public::default()
    }

    pub fn sr25519_sign(
        id: KeyTypeId,
        pubkey: &sr25519::Public,
        msg: &[u8],
    ) -> Option<sr25519::Signature> {
        warn!("crypto::sr25519_sign unimplemented");
        Some(sr25519::Signature::default())
    }

    pub fn sr25519_verify(sig: &sr25519::Signature, msg: &[u8], pubkey: &sr25519::Public) -> bool {
        warn!("crypto::sr25519_verify unimplemented");
        true
    }

    pub fn secp256k1_ecdsa_recover(sig: &[u8; 65], msg: &[u8; 32]) -> Result<[u8; 64], EcdsaVerifyError> {
        warn!("crypto::secp256k1_ecdsa_recover unimplemented");
        Ok([0; 64])
    }

    pub fn secp256k1_ecdsa_recover_compressed(sig: &[u8; 65], msg: &[u8; 32]) -> Result<[u8; 33], EcdsaVerifyError> {
        warn!("crypto::secp256k1_ecdsa_recover unimplemented");
        Ok([0; 33])
    }
}

pub mod offchain{
    use super::*;

    pub fn is_validator() -> bool {
        warn!("offchain::is_validator unimplemented");
        false
    }

    pub fn submit_transaction(data: Vec<u8>) -> Result<(), ()> {
        warn!("offchain::submit_transaction unimplemented");
        Err(())
    }

    pub fn network_state() -> Result<OpaqueNetworkState, ()> {
        warn!("offchain::network_state unimplemented");
        Err(())
    }

    pub fn timestamp() -> offchain::Timestamp {
        warn!("offchain::timestamp unimplemented");
        offchain::Timestamp::default()
    }

    pub fn sleep_until(deadline: offchain::Timestamp) {
        warn!("offchain::sleep_until unimplemented");
    }

    pub fn random_seed() -> [u8; 32] {
        warn!("offchain::random_seed unimplemented");
        [0;32]
    }

    pub fn local_storage_set(kind: offchain::StorageKind, key: &[u8], value: &[u8]) {
        warn!("offchain::local_storage_set unimplemented");
    }

    pub fn local_storage_compare_and_set(
        kind: offchain::StorageKind,
        key: &[u8],
        old_value: Option<&[u8]>,
        new_value: &[u8],
    ) -> bool {
        warn!("offchain::local_storage_compare_and_set unimplemented");
        false
    }

    pub fn local_storage_get(kind: offchain::StorageKind, key: &[u8]) -> Option<Vec<u8>> {
        warn!("offchain::local_storage_get unimplemented");
        None
    }

    pub fn http_request_start(
        method: &str,
        uri: &str,
        meta: &[u8]
    ) -> Result<offchain::HttpRequestId, ()> {
        warn!("offchain::http_request_start unimplemented");
        Err(())
    }

    pub fn http_request_add_header(
        request_id: offchain::HttpRequestId,
        name: &str,
        value: &str
    ) -> Result<(), ()> {
        warn!("offchain::http_request_add_header unimplemented");
        Err(())
    }

    pub fn http_request_write_body(
        request_id: offchain::HttpRequestId,
        chunk: &[u8],
        deadline: Option<offchain::Timestamp>
    ) -> Result<(), offchain::HttpError> {
        warn!("offchain::http_request_write_body unimplemented");
        Err(offchain::HttpError::IoError)
    }

    pub fn http_response_wait(
        ids: &[offchain::HttpRequestId],
        deadline: Option<offchain::Timestamp>
    ) -> Vec<offchain::HttpRequestStatus> {
        warn!("offchain::http_response_wait unimplemented");
        Vec::new()
    }

    pub fn http_response_headers(
        request_id: offchain::HttpRequestId
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        warn!("offchain::http_response_wait unimplemented");
        Vec::new()
    }

    pub fn http_response_read_body(
        request_id: offchain::HttpRequestId,
        buffer: &mut [u8],
        deadline: Option<offchain::Timestamp>
    ) -> Result<usize, offchain::HttpError> {
        warn!("offchain::http_response_read_body unimplemented");
        Err(offchain::HttpError::IoError)
    }
}

pub mod misc {
    use super::*;
    /// The current relay chain identifier.
    pub fn chain_id() -> u64 {
        warn!("OtherApi::chain_id unimplemented");
        0
    }

    /// Print a number.
    pub fn print_num(val: u64) {
        debug!(target: "runtime", "{}", val);
    }

    /// Print any valid `utf8` buffer.
    pub fn print_utf8(utf8: &[u8]) {
        if let Ok(data) = std::str::from_utf8(utf8) {
            debug!(target: "runtime", "{}", data)
        }
    }

    /// Print any `u8` slice as hex.
    pub fn print_hex(data: &[u8]) {
        debug!(target: "runtime", "{:?}", data);
    }
}

pub mod logging {
    use super::*;
    use primitives::LogLevel;
    /// Request to print a log message on the host.
    ///
    /// Note that this will be only displayed if the host is enabled to display log messages with
    /// given level and target.
    ///
    /// Instead of using directly, prefer setting up `RuntimeLogger` and using `log` macros.
    pub fn log(level: LogLevel, target: &str, message: &[u8]) {
        if let Ok(message) = std::str::from_utf8(message) {
            debug!(
				target: target,
//				Level::from(level),
				"{}",
				message,
			)
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use primitives::{H256, map};
    use primitives::storage::well_known_keys::CODE;

    use super::*;

    #[test]
    fn commit_should_work() {
        let mut ext = SgxExternalities::default();
        ext.set_storage(b"doe".to_vec(), b"reindeer".to_vec());
        ext.set_storage(b"dog".to_vec(), b"puppy".to_vec());
        ext.set_storage(b"dogglesworth".to_vec(), b"cat".to_vec());
        const ROOT: [u8; 32] = hex!("39245109cef3758c2eed2ccba8d9b370a917850af3824bc8348d505df2c298fa");

        assert_eq!(ext.storage_root(), H256::from(ROOT));
    }

    #[test]
    fn set_and_retrieve_code() {
        let mut ext = SgxExternalities::default();

        let code = vec![1, 2, 3];
        ext.set_storage(CODE.to_vec(), code.clone());

        assert_eq!(&ext.storage(CODE).unwrap(), &code);
    }


    #[test]
    fn basic_externalities_is_empty() {
        // Make sure no values are set by default in `BasicExternalities`.
        let (storage, child_storage) = SgxExternalities::new(
            Default::default(),
            Default::default(),
        ).into_storages();
        assert!(storage.is_empty());
        assert!(child_storage.is_empty());
    }
}
