/*
   Copyright 2019 Supercomputing Systems AG

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

#[macro_use]
extern crate clap;
use clap::App;

extern crate sgx_types;
extern crate sgx_urts;
extern crate sgx_crypto_helper;

mod constants;
mod utils;
mod enclave_api;
mod init_enclave;
mod create_keys;

use std::str;
use sgx_types::*;
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use constants::*;
use utils::file_exists;
use enclave_api::*;
use init_enclave::init_enclave;
use create_keys::create_rsa3072_keypair;

fn main() {
    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

    if matches.is_present("worker") {
        println!("* Starting substraTEE-worker");
        println!("");
        worker();
        println!("* Worker finished");
    }
    else {
        println!("For options: use --help");
    }
}

fn worker() -> () {
    // ------------------------------------------------------------------------
    // initialize the enclave
    println!("");
    println!("*** Starting enclave");
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful. EID = {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x);
            return;
        },
    };

    // ------------------------------------------------------------------------
    // check if the sealed rsa3072 file exists and create it if needed
    println!("");
    println!("*** RSA3072 key generation/use");
    match file_exists(RSA3072_SEALED_KEY_FILE) {
        false => create_rsa3072_keypair(enclave.geteid()),
        true  => println!("[+] File '{}' already exist", RSA3072_SEALED_KEY_FILE)
    }

    // ------------------------------------------------------------------------
    // check if schnorrkel key is present -> used for signing the transaction
    println!("");
    println!("*** Schnorrkel key generation/use");
    println!("**** TODO");

    // ------------------------------------------------------------------------
    // subscribe to event and react on fireing
    println!("");
    println!("*** Subscribe to substraTEE-proxy event");
    println!("**** TODO");

    let mut ciphertext : Vec<u8> = Vec::new();
    let mut retval = sgx_status_t::SGX_SUCCESS;

    // ------------------------------------------------------------------------
    // encrypt a test message
    // only used for testing purpose
    println!("");
    println!("*** Encrypt test message");
    println!("**** TO BE REMOVED");
    let pubkey_size = 8192;
    let mut pubkey = vec![0u8; pubkey_size as usize];

    let result = unsafe {
        get_rsa_encryption_pubkey(enclave.geteid(),
                      &mut retval,
                      pubkey.as_mut_ptr(),
                      pubkey_size
                      )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();
    // we actually should only get the pubkey here
    //let rsa_pubkey = rsa_keypair.to_pubkey();
    //self, plaintext: &[u8], ciphertext: &mut Vec<u8>

    let mut ciphertext : Vec<u8> = Vec::new();
    let plaintext = b"Alice,42".to_vec();
    rsa_keypair.encrypt_buffer(&plaintext, &mut ciphertext).unwrap();
    println!("ciphertext = {:?}", ciphertext);
    // ------------------------------------------------------------------------

    // ------------------------------------------------------------------------
    // decrypt the payload of the message
    // encoded message 'b"Alice, 42"'
    println!("");
    println!("*** Decrypt the payload");
    // ciphertext = [35, 238, 142, 104, 209, 142, 188, 217, 158, 7, 107, 10, 12, 166, 221, 243, 6, 226, 186, 246, 237, 96, 37, 245, 134, 4, 113, 61, 182, 177, 228, 98, 209, 76, 15, 232, 184, 172, 110, 221, 152, 186, 106, 248, 173, 140, 41, 17, 97, 169, 140, 150, 138, 94, 27, 243, 196, 30, 68, 56, 13, 206, 32, 0, 255, 144, 140, 79, 76, 55, 219, 246, 14, 222, 234, 28, 187, 235, 117, 158, 71, 26, 229, 192, 209, 129, 138, 162, 184, 201, 95, 5, 62, 171, 193, 156, 237, 112, 115, 4, 222, 101, 171, 166, 79, 91, 102, 137, 241, 144, 96, 232, 179, 216, 216, 152, 246, 243, 155, 120, 133, 117, 65, 145, 176, 138, 228, 253, 117, 121, 21, 217, 141, 189, 55, 242, 233, 148, 121, 181, 197, 79, 134, 97, 169, 195, 71, 112, 166, 175, 147, 128, 178, 212, 224, 12, 73, 159, 242, 31, 124, 106, 134, 122, 154, 16, 108, 39, 185, 32, 8, 106, 26, 0, 235, 142, 106, 232, 6, 45, 6, 221, 100, 17, 21, 78, 100, 204, 176, 193, 91, 185, 61, 51, 57, 143, 146, 60, 170, 58, 222, 1, 182, 74, 181, 159, 82, 23, 135, 62, 115, 44, 143, 237, 96, 248, 250, 197, 225, 41, 208, 103, 234, 135, 86, 115, 173, 115, 72, 34, 230, 205, 210, 236, 136, 241, 65, 136, 42, 53, 148, 240, 73, 220, 105, 114, 167, 109, 209, 37, 186, 177, 100, 242, 9, 46, 0, 161, 90, 110, 243, 32, 164, 61, 102, 17, 139, 219, 210, 16, 118, 110, 156, 153, 169, 43, 242, 209, 10, 174, 167, 30, 250, 137, 25, 53, 86, 202, 125, 180, 208, 178, 111, 132, 150, 197, 182, 156, 248, 177, 225, 45, 187, 13, 235, 2, 126, 190, 136, 36, 140, 229, 22, 7, 181, 207, 115, 126, 205, 229, 168, 251, 105, 201, 134, 201, 197, 166, 166, 200, 60, 188, 86, 180, 175, 186, 238, 117, 210, 8, 202, 44, 233, 190, 17, 17, 209, 179, 185, 0, 169, 42, 191, 174, 78, 153, 128, 212, 237, 39, 87, 182, 251, 10, 100, 12, 79, 70, 242, 154, 243, 83, 123, 183, 131, 237, 197, 175, 116, 108, 45, 213, 172, 26].to_vec();

    let file = String::from(RSA3072_SEALED_KEY_FILE);

    let result = unsafe {
        decrypt(enclave.geteid(),
                &mut retval,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as u32
                )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => println!("[+] Message decoded and processed in the enclave."),
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    // ------------------------------------------------------------------------
    // compose an extrinsic with the hash of the initial payload
    println!("");
    println!("*** Compose extrinsic");
    println!("**** TODO");

    // ------------------------------------------------------------------------
    // send the extrinsic
    println!("");
    println!("*** Send extrinsic");
    println!("**** TODO");

    // ------------------------------------------------------------------------
    // destroy the enclave
    println!("");
    println!("*** Destroy enclave");
    enclave.destroy();
}
