# Trusted Rpc Interface
This document contains information about the trusted worker json-rpc interface. The trusted worker server is a tls websocket directly running in the enclave.

The server expects an json-rpc call of the following format:

`{"jsonrpc": "2.0", "method": "author_pendingExtrinsics", "params": ["5Ki5bf4dcY9eyrqBRe6Xbr5accvo42XZb86eXv5mkTJo"], "id": 1}`

The rpc method names of the worker are chosen such that they match the naming scheme of the rpc calls of substrate: https://docs.substrate.io/v3/runtime/custom-rpcs/
## Available RPC calls

### General
- `rpc_methods` (no params): List all available (though maybe unimplemented) rpc methods. Example: `{"jsonrpc": "2.0", "method": "rpc_methods","id": 1}`
- `author_getShieldingKey` (no params): Retrieves the public shielding key, which the client can use to encrypt it's messages before sending it to the worker.
- `author_getMuRaUrl` (no params): Retrieves the mutual remote attestation url of the worker (Only needed by fellow validateers).
- `author_getUntrustedUrl` (no params): Retrieves the untrusted ws url of the worker (Only needed by fellow validateers).

### Sidechain related
A sidechain related call always enters our so called trusted operation pool. To provide as much privacy as possible, all calls are expected to be encrypted (with the shielding key that can be retrieved with `author_getShieldingKey`) and have the exact same structure, be it a getter or a call. This adds some complexity to the request structure but allows to expand calls and getters without having to change any networking and caching functionalities in our codebase (see the [Turtorial](https://book.integritee.network/howto_stf.html) on how to expand `Getters` and `Calls` according to the users need).

#### Request
All rpc params are expected to be a [substrate codec](https://docs.substrate.io/v3/advanced/scale-codec/) encoded [Request](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/core-primitives/types/src/lib.rs#L64-L68), with the parameters:
- shard :  `H256` : H256 of a state
- cyphertext : `Vec<u8>` : with the shielding key encrypted `TrustedOperation`.


#### Trusted Operation
A [`TrustedOperation`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L112-L118) may be an indirect / direct `TrustedCallSigned` or a `Getter`. For the direct rpc calls, only direct calls should be used.

#### Getter
[`Getters`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L144-L149) may be `trusted` or `public`. All trusted getters must be signed by the client, forming a [`TrustedGetterSigned`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L227-L231), which contains the [`TrustedGetter`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L204-L210) itself and the `Signature` of the sender. The currently supported trusted Getters are:
- `free_balance` of an account.
- `reservered_balance` of an account.
- current `nonce` of an account.

#### Trusted Calls
A [`TrustedCallSigned`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L243-L248) contains, in contrast to the `Getter`, not two but three components:
- nonce (to prevent replay attacks)
- [signature](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L195-L200) of the call (contains the nonce, mrenclave as well as the shard)
- the `TrustedCall` itself

The current implementation of the [`TrustedCall`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L169-L176) supports the following calls:
- `balance_set_balance` set the balance of an account (signer, beneficary, free balance, reserved balance)
- `balance_transfer` transfer balance from first account to second account
- `balance_unshield` transfer balance from sidechain (incognito) account to parentchain (public) account.
- `balance_shield` transfer balance from parentchain (public) account to sidechain (incognito) account.

#### RPC Methods
The following rpc calls are available:
  - `author_submitAndWatchExtrinsic`, params: `Vec<String>`(hex encoded `Request`). Sends an extrinsic (`Call` or `Getter`). The server will keep the wss connection open and send status updates.
  - `author_submitExtrinsic`, params: `Vec<String>` (hex encoded `Request`). Sends an extrinsic (`Call` or `Getter`). The server will close the connection immediately after the first response.
   - `author_pendingExtrinsics`, params: `Vec<String>` (Vector of base58 shards as strings). Returns all pending operations of the listed shards in the top pool.
## Rpc Response
The server response is a json rpc response containing a [substrate codec](https://docs.substrate.io/v3/advanced/scale-codec/) encoded [`RpcReturnValue`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/core-primitives/types/src/rpc.rs#L8-L14) as param. It has the following parameters:
- `value`: Encoded return value, depends on the called function and status.
- `do_watch`: If not true, the server will close the connection after sending this response.
- `status`: [`DirectRequestStatus`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/core-primitives/types/src/lib.rs#L87-L95). Indicates the status of the request.

For all rpc methods the following holds true:  If the status is an `Error`, the value is an encoded `String` error message. For non-sidechain related rpc calls, the only other status used, is `Ok`. If `Ok` is returned, the value will also contain an encoded `String`, containing the requested response, be it an url or a shielding key.

The `TrustedOperationStatus` is only used for sidechain related responses.

### Sidechain related responses
If the `status` equals the enum [`TrustedOperationStatus`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/core-primitives/types/src/lib.rs#L98-L123), the value contains the encoded Hash of the corresponding `TrustedOperation`. The status `Ok` is used for `Getter` return values. In this case, the return value is an encoded  `Option` containing the encoded expected return value. The balance getter for example would be an encoded `Balance` type ( = `u128`).
