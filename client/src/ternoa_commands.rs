//  Copyright (c) 2019 Alain Brenzikofer
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use crate::ternoa_implementation::nft::create::create;
use crate::ternoa_implementation::nft::mutate::mutate;
use crate::ternoa_implementation::nft::transfer::transfer;
use crate::VERSION;
use clap::{App, AppSettings, Arg, ArgMatches};
use clap_nested::{Command, Commander, MultiCommand};
use log::*;
use sp_application_crypto::sr25519;
use substrate_api_client::Api;

const NFTID_ARG_NAME: &str = "nftid";
const FILENAME_ARG_NAME: &str = "filename";
const URL_ARG_NAME: &str = "url";

const OWNER: &str = "owner";
const TO: &str = "to";
const FROM: &str = "from";

/// creates an inputfile.cyphertext and inputfile.aes256 with the symmetric key and stores it locally
/// INPUT: file path as String
pub fn encrypt_cmd() -> Command<'static, str> {
    Command::new("encrypt")
        .description("Generates an AES256 key, encrypts and stores the input data")
        .options(|app| {
            app.setting(AppSettings::ColoredHelp).arg(
                Arg::with_name("filepath")
                    .takes_value(true)
                    .required(true)
                    .value_name("STRING")
                    .help("filepath of the file to be encrypted"),
            )
        })
        .runner(|_args: &str, matches: &ArgMatches<'_>| {
            let path: &str = matches.value_of("filepath").unwrap();
            debug!("entering encryption function, received filepath: {}", path);
            // ENCRYPT FUNCTION HERE #2
            Ok(())
        })
}

/// decrypts cyphertext using the aes256 key stored in inputfile.aes256. for debug only
/// INPUT: file path as String
/// Optional:
/// reads key shares from second file (=keyshares file), shamir-combines the shares
/// into the original assuming the exact number of shares given that is needed
/// INPUT:  file path to decrypt as String
///         shamir key shares file path
pub fn decrypt_cmd() -> Command<'static, str> {
    Command::new("decrypt")
        .description("decrypts the entered file with stored inputfile.aes256 key")
        .options(|app| {
            app.arg(
                Arg::with_name("filepath")
                    .takes_value(true)
                    .required(true)
                    .value_name("STRING")
                    .help("filepath of the file to be decrypted"),
            )
            .arg(
                Arg::with_name("keysharesfile")
                    .takes_value(true)
                    .required(false)
                    .value_name("STRING")
                    .help("filepath of the file containing the key shares"),
            )
        })
        .runner(|_args: &str, matches: &ArgMatches<'_>| {
            let path: &str = matches.value_of("filepath").unwrap();
            let _keysharesfile = match matches.value_of("keysharesfile") {
                Some(keysharesfile) => {
                    debug!(
                        "entering decrypt shamir function, received filepaths: {},{}",
                        path, keysharesfile
                    );
                }
                None => {
                    debug!("entering decrypt function, received filepath: {}", path);
                }
            };
            Ok(())
        })
}

/// Adds all nft commands
pub fn nft_commands() -> MultiCommand<'static, str, str> {
    Commander::new()
        .options(|app| {
            app.setting(AppSettings::ColoredHelp)
                .name("ternoa-client")
                .version(VERSION)
                .author("Supercomputing Systems AG <info@scs.ch>")
                .about("nft calls to ternoa chain")
        })
        .add_cmd(
            Command::new("create")
                .description("Create a new NFT with the provided filename.")
                .options(|app| {
                    let app_with_owner = add_account_id_arg(app, OWNER);
                    add_filename_arg(app_with_owner)
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let chain_api = get_ternoa_chain_api(matches);
                    // Create a new NFT with the provided details. An ID will be auto
                    // generated and logged as an event, The caller of this function
                    // will become the owner of the new NFT.
                    // INPUT:  AccountId (owner)
                    //         ASCII encoded URI to fetch additional metadata.
                    let owner_ss58: &str = matches.value_of(OWNER).unwrap();
                    let filename: &str = matches.value_of("filename").unwrap();
                    debug!(
                        "entering nft create function, owner: {}, filename: {}",
                        owner_ss58, filename
                    );

                    let nft_id = create(owner_ss58, filename, chain_api).unwrap();
                    info!("NFT was created {}", nft_id);

                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("mutate")
                .description("Updates NFT to new filename")
                .options(|app| {
                    let app_with_owner = add_account_id_arg(app, OWNER);
                    let app_with_nftid = add_nft_id_arg(app_with_owner);
                    add_filename_arg(app_with_nftid)
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    // Update the details included in an NFT. Must be called by the owner of
                    // the NFT and while the NFT is not sealed.
                    // INPUT:  AccountId (owner)
                    //         NFTId
                    //         Filename
                    let chain_api = get_ternoa_chain_api(matches);
                    let owner_ss58: &str = matches.value_of(OWNER).unwrap();
                    let nft_id = get_nft_id_from_matches(matches);
                    let filename: &str = matches.value_of("filename").unwrap();
                    debug!(
                        "entering nft mutate function, owner: {}, filename: {}, id: {:?}",
                        owner_ss58, filename, nft_id
                    );
                    mutate(owner_ss58, nft_id, filename, chain_api);
                    info!("NFT was mutated {}", nft_id);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("transfer")
                .description("Create a new NFT with the provided details.")
                .options(|app| {
                    let app_with_from = add_account_id_arg(app, FROM);
                    let app_with_to = add_account_id_arg(app_with_from, TO);
                    add_nft_id_arg(app_with_to)
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    // Transfer an NFT from an account to another one. Must be called by the
                    // actual owner of the NFT.
                    // INPUT:  AccountId (current owner)
                    //         AccountId (new owner)
                    //         NFTId
                    let chain_api = get_ternoa_chain_api(matches);
                    let from: &str = matches.value_of(FROM).unwrap();
                    let to: &str = matches.value_of(TO).unwrap();
                    let nft_id = get_nft_id_from_matches(matches);
                    debug!(
                        "entering nft transfer function, owner: {}, new owner: {}, id: {:?}",
                        from, to, nft_id
                    );
                    transfer(from, to, nft_id, chain_api);
                    info!("NFT was transferred {} to {}", nft_id, to);
                    Ok(())
                }),
        )
        .into_cmd("nft")
}

/// Adds all keyvault commands
pub fn keyvault_commands() -> MultiCommand<'static, str, str> {
    Commander::new()
        .options(|app| {
            app.setting(AppSettings::ColoredHelp)
                .name("ternoa-client")
                .version(VERSION)
                .author("Supercomputing Systems AG <info@scs.ch>")
                .about("keyvault calls to worker enclave")
        })
        .add_cmd(
            Command::new("check")
                .description("checks if keyshare for given nftid is stored in url keyvault")
                .options(|app| {
                    let app_with_nftid = add_nft_id_arg(app);
                    add_url_arg(app_with_nftid)
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    // check if the key share for NFTId is stored in the keyvault with <url>. exit code 1 if negative
                    // INPUT:  NFTId (u32)
                    //         url
                    let nftid = get_nft_id_from_matches(matches);
                    let url: &str = matches.value_of(URL_ARG_NAME).unwrap();
                    debug!(
                        "entering keyvault check function, nftid: {}, urll: {}",
                        nftid, url
                    );
                    // KEYVAULT CHECK CODE HERE

                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("get")
                .description("returns single key share")
                .options(|app| {
                    let app_with_nftid = add_nft_id_arg(app);
                    let app_with_owner = add_account_id_arg(app_with_nftid, OWNER);
                    add_url_arg(app_with_owner)
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    // returns single key share
                    // INPUT:  NFTId (u32)
                    //         owner
                    //         enclave url
                    let nftid = get_nft_id_from_matches(matches);
                    let owner_ss58: &str = matches.value_of(OWNER).unwrap();
                    let url: &str = matches.value_of(URL_ARG_NAME).unwrap();
                    debug!(
                        "entering keyvault get funtciotn, nftid: {}, owner: {}, urll: {}",
                        nftid, owner_ss58, url
                    );
                    // KEYVAULT GET CODE HERE
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list")
                .description("lists urls of registered enclaves, one per line")
                .runner(|_args: &str, _matches: &ArgMatches<'_>| {
                    // Lists urls of registered enclaves, one per line
                    debug!("entering keyvault list commands");
                    // LIST IMPLEMENATION HERE :
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("provision")
                .description("provisions all keyvaults and verifies")
                .options(|app| {
                    let app_with_nftid = add_nft_id_arg(app);
                    app_with_nftid
                        .arg(
                            Arg::with_name("urllist")
                                .takes_value(true)
                                .required(true)
                                .value_name("List of Strings")
                                .help("list of enclave url lists"),
                        )
                        .arg(
                            Arg::with_name("needed_keys")
                                .takes_value(true)
                                .required(true)
                                .value_name("u32")
                                .help("specifies the minimum necessary recovery keys < #urllist"),
                        )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    // Will read aes256 key, shamir-split shares, provision all keyvaults and verify
                    // N: number of shares needed to recover key (must be smaller than number of urls)
                    // INPUT:  NFTId (u32)
                    //         urllist ("[...]")
                    //         N
                    let nftid = get_nft_id_from_matches(matches);
                    let urllist: &str = matches.value_of("urllist").unwrap();
                    let needed_keys: &str = matches.value_of("needed_keys").unwrap();
                    debug!(
                        "entering keyvault provision, nftid: {}, urllist: {}, N: {:?}",
                        nftid, urllist, needed_keys
                    );
                    // KEYVAULT PROVISION CODE HERE
                    Ok(())
                }),
        )
        .into_cmd("keyvault")
}

pub fn get_nft_id_from_matches(matches: &ArgMatches<'_>) -> u32 {
    get_u32_from_str(matches.value_of(NFTID_ARG_NAME).unwrap())
}

fn get_u32_from_str(arg: &str) -> u32 {
    arg.parse::<u32>()
        .unwrap_or_else(|_| panic!("failed to convert {} into an integer", arg))
}

pub fn add_nft_id_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name(NFTID_ARG_NAME)
            .takes_value(true)
            .required(true)
            .value_name("U32")
            .help("NFTId"),
    )
}

pub fn add_account_id_arg<'a, 'b>(app: App<'a, 'b>, name: &'a str) -> App<'a, 'b> {
    app.arg(
        Arg::with_name(name)
            .takes_value(true)
            .required(true)
            .value_name("SS58")
            .help("AccountId in ss58check format"),
    )
}

pub fn add_filename_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name(FILENAME_ARG_NAME)
            .takes_value(true)
            .required(true)
            .value_name("STRING")
            .help("new file name to be contained in the NFT"),
    )
}

pub fn add_url_arg<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name(URL_ARG_NAME)
            .takes_value(true)
            .required(true)
            .value_name("STRING")
            .help("url of sgx keyvault enclave"),
    )
}

//Duplicate code. See get_chain_api in main.rs.
fn get_ternoa_chain_api(matches: &ArgMatches<'_>) -> Api<sr25519::Pair> {
    let url = format!(
        "{}:{}",
        matches.value_of("node-url").unwrap(),
        matches.value_of("node-port").unwrap()
    );
    info!("connecting to {}", url);
    Api::<sr25519::Pair>::new(url).unwrap()
}
