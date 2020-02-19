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
use std::vec::Vec;

use sgx_types::sgx_status_t;

use log::*;

use crate::Hash;

pub fn hash_from_slice(hash_slize: &[u8]) -> Hash {
    let mut g = [0; 32];
    g.copy_from_slice(&hash_slize[..]);
    Hash::from(&mut g)
}

pub fn write_slice_and_whitespace_pad(writable: &mut [u8], data: Vec<u8>) {
    if data.len() > writable.len() {
        panic!("not enough bytes in output buffer for return value");
    }
    let (left, right) = writable.split_at_mut(data.len());
    left.clone_from_slice(&data);
    // fill the right side with whitespace
    right.iter_mut().for_each(|x| *x = 0x20);
}

pub trait UnwrapOrSgxErrorUnexpected {
    type ReturnType;
    fn sgx_error(self) -> Result<Self::ReturnType, sgx_status_t>;
    fn sgx_error_with_log(self, err_mgs: &str) -> Result<Self::ReturnType, sgx_status_t>;
}

impl<T> UnwrapOrSgxErrorUnexpected for Option<T> {
    type ReturnType = T;
    fn sgx_error(self) -> Result<Self::ReturnType, sgx_status_t> {
        match self {
            Some(r) => Ok(r),
            None => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
        }
    }

    fn sgx_error_with_log(self, log_msg: &str) -> Result<Self::ReturnType, sgx_status_t> {
        match self {
            Some(r) => Ok(r),
            None => {
                error!("{}", log_msg);
                Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
            }
        }
    }
}

impl<T, S> UnwrapOrSgxErrorUnexpected for Result<T, S> {
    type ReturnType = T;
    fn sgx_error(self) -> Result<Self::ReturnType, sgx_status_t> {
        match self {
            Ok(r) => Ok(r),
            Err(_) => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
        }
    }

    fn sgx_error_with_log(self, log_msg: &str) -> Result<Self::ReturnType, sgx_status_t> {
        match self {
            Ok(r) => Ok(r),
            Err(_) => {
                error!("{}", log_msg);
                Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
            }
        }
    }
}
