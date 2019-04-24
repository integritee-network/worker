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
//extern crate sgx_tseal;
extern crate dirs;
extern crate rust_base58;
extern crate crypto;
extern crate sgx_crypto_helper;
extern crate substra_tee_worker;

use sgx_types::*;
use sgx_urts::SgxEnclave;
//use sgx_tseal::{SgxSealedData};
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::str;
use rust_base58::{ToBase58, FromBase58};
use crypto::ed25519::{keypair, verify};
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use substra_tee_worker::{
    generate_keypair,
    init_enclave::*,
    utils::keyfile_exists,
    utils::get_affirmation
};

extern {
    fn create_sealed_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
        sealed_seed: * mut u8, sealed_seed_size: u32,
        pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t;

    fn sign(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
        sealed_seed: * mut u8, sealed_seed_size: u32,
        msg: * mut u8, msg_size: u32,
        signature: * mut u8, signature_size: u32) -> sgx_status_t;

    fn get_rsa_encryption_pubkey(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
        pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t;

    fn decrypt(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
        ciphertext: * mut u8, ciphertext_size: u32) -> sgx_status_t;

}

fn sealed_key() {
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

    let sealed_seed_size = 1024;
    let mut sealed_seed = vec![0u8; sealed_seed_size as usize];
    let pubkey_size = 32;
    let mut pubkey = vec![0u8; pubkey_size as usize];

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        create_sealed_key(enclave.geteid(),
                      &mut retval,
                      sealed_seed.as_mut_ptr(),
                      sealed_seed_size,
                      pubkey.as_mut_ptr(),
                      pubkey_size,
                      )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    // importing sgx_tseal causes collision with std
    //let sdata = SgxSealedData::<u8>::from_raw_sealed_data_t(sealed_seed.as_mut_ptr() as * mut sgx_sealed_data_t, sealed_seed_size);
    println!("[+] enclave returned pubkey: {:?}", pubkey.to_base58());

    // now let the enclave sign our message
    //let msg = b"This message is true";

    //let mut msg = vec![0u8; msg_size as usize];
    let mut msg = b"This message is true".to_vec();

    println!("let enclave sign message: {}", str::from_utf8(&msg).unwrap());

    //allocate signature
    let signature_size = 64;
    let mut signature = vec![0u8; signature_size as usize];

    let result = unsafe {
        sign(enclave.geteid(),
                      &mut retval,
                      sealed_seed.as_mut_ptr(),
                      sealed_seed_size,
                      msg.as_mut_ptr(),
                      msg.len() as u32,
                      signature.as_mut_ptr(),
                      signature_size
                      )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    // verify signature with pubkey
    let result = verify(&msg[..], &pubkey[..], &signature[..]);
    match result {
        true => {println!("[+] enclave signature is correct!");}
        _ => {println!("[-] enclave signature is incorrect!");}
    }

    //////////////////////////////////777
    // retrieve RSA pubkey

    //allocate signature
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
    let plaintext = b"This message is confidential".to_vec();
    rsa_keypair.encrypt_buffer(&plaintext, &mut ciphertext).unwrap();

    let result = unsafe {
        decrypt(enclave.geteid(),
                      &mut retval,
                      ciphertext.as_mut_ptr(),
                      ciphertext.len() as u32
                      )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    enclave.destroy();
}

fn main() {
    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

    let keyfile: String  = matches.value_of("keyfile").unwrap_or("./encrypted_keypair").to_string();

    if matches.is_present("sealedkey") {
        println!("* Starting substraTEE-worker");
        println!("** Generating sealed key");
        println!("");
        sealed_key();
    }
    else if matches.is_present("generate") {
        println!("* Starting substraTEE-worker");
        println!("** Generating key pair");
        println!("");
        generate(&keyfile);
    }
    else {
        println!("For options: use --help");
    }
}

fn generate(path: &String) -> () {
    match keyfile_exists(&path) {
        false => println!("keyfile '{}' does NOT exist", &path),
        true  => {
            println!("[!] WARNING! File '{}' exists and will be overwritten!", &path);
            match get_affirmation("This cannot be undone!".to_string()) {
                false => println!("[-] Nothing will be done. exiting"),
                true  => {
                    println!("[+] File will be overwritten");
                    match generate_keypair::run(&path) {
                        Ok(_) => println!("[+] Key pair successfully saved to {}", &path),
                        Err(e) => println!("[-] Error generating keypair:\n\t{:?}", e)
                    };
                }
            }
        }
    }

}
