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

use codec::{Decode, Encode};
use substratee_stf::{Getter, ShardIdentifier};

#[derive(Encode, Decode, Clone, Debug)]
pub enum ClientRequest {
    PubKeyWorker,
    MuRaPortWorker,
    StfState(Getter, ShardIdentifier), // (trusted_getter_encrypted, shard)
}
