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

use std::result;
use error::AppError;
use init_enclave::init_enclave;

use std::fs;

type Result<T> = result::Result<T, AppError>;

pub fn run(path: &String) -> Result<()> {
    println!(" * generate_keypair:run()");
    println!(" * using path {}", path);

    init_enclave();

    save_keypair(&path);

    Ok(())
}

fn save_keypair(path: &String) -> Result<()> {
    Ok(fs::write(path, "This will be the sealed keygen")?)
}