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

static ENCLAVE_FILE: &'static str = "./bin/enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "./bin/enclave.token";

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

fn init_enclave() -> SgxResult<SgxEnclave> {

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    let mut home_dir = path::PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    let token_file: path::PathBuf = home_dir.join(ENCLAVE_TOKEN);;
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = try!(SgxEnclave::create(ENCLAVE_FILE,
                                          debug,
                                          &mut launch_token,
                                          &mut launch_token_updated,
                                          &mut misc_attr));

    // Step 3: save the launch token if it is updated
    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}

fn sealed_key() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
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

    if matches.is_present("sealedkey") {
        println!("* Starting substraTEE-worker");
        println!("** Generating sealed key");
        println!("");
        sealed_key();
    }
    else {
        println!("For options: use --help");
    }
}
