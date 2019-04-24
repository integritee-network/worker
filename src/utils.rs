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
use std::path::Path;
use std::io::{stdin, stdout, Write};

type Result<T> = result::Result<T, AppError>;

pub fn keyfile_exists(path: &String) -> bool {
    Path::new(path).exists()
}

pub fn get_affirmation(warn_msg: String) -> bool {
    let mut s = String::new();
    print!("[!] WARNING! {} Proceed? y/n ", warn_msg);
    let _ = stdout().flush();
    stdin().read_line(&mut s).expect("[-] You did not enter a correct string");
    if s.trim() == "y" || s.trim() == "yes" || s.trim() == "Y" || s.trim() == "YES" || s.trim() == "Yes" { true } else { false }
}
