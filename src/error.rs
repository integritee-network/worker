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

use hex;
use reqwest;
use sgx_types::sgx_status_t;
use std::error::Error;
use std::{fmt, io, num};

#[derive(Debug)]
pub enum AppError {
    Io(io::Error),
    Custom(String),
    SGXError(sgx_status_t),
    HexError(hex::FromHexError),
    ReqwestError(reqwest::Error),
    ParseINTError(num::ParseIntError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            AppError::Custom(ref msg) => msg.clone(),
            AppError::Io(ref e) => format!("I/O error: {}", e),
            AppError::SGXError(ref e) => format!("SGX error: {}", e),
            AppError::HexError(ref e) => format!("Hex error: {}", e),
            AppError::ReqwestError(ref e) => format!("Reqwest error: {}", e),
            AppError::ParseINTError(ref e) => format!("ParseInt error: {}", e),
        };
        f.write_fmt(format_args!("{}", msg))
    }
}

impl Error for AppError {
    fn description(&self) -> &str {
        "Program Error"
    }
}

impl Into<String> for AppError {
    fn into(self) -> String {
        format!("{}", self)
    }
}

impl From<num::ParseIntError> for AppError {
    fn from(err: num::ParseIntError) -> AppError {
        AppError::ParseINTError(err)
    }
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> AppError {
        AppError::Io(err)
    }
}

impl From<sgx_status_t> for AppError {
    fn from(err: sgx_status_t) -> AppError {
        AppError::SGXError(err)
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> AppError {
        AppError::HexError(e)
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> AppError {
        AppError::ReqwestError(e)
    }
}
