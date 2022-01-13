# Trusted Rpc Interface
This document contains information about the trusted worker json-rpc interface. The trusted worker server is a tls websocket directly running within the enclave.

The server expects an json-rpc call of the following format:

`{"jsonrpc": "2.0", "method": "author_pendingExtrinsics", "params": ["5Ki5bf4dcY9eyrqBRe6Xbr5accvo42XZb86eXv5mkTJo"], "id": 1}`

The workers methods are aligned to match as much as possible the substrate rpc calls: https://docs.substrate.io/v3/runtime/custom-rpcs/

Hence, just like in substrate, all available rpc methods can get listed with the rpc call `rpc_methods`:
`{"jsonrpc": "2.0", "method": "rpc_methods","id": 1}`

Currently, not all listed methods have a useful implementation yet. The most important ones are listed in following.

## Available RPC calls

# General
- `rpc_methods` (no params): List all available (though maybe unimplemented) rpc methods.
- `author_getShieldingKey` (no params): Retrieves the public shielding key, which the client can use to encrypt it's messages before sending it to the worker.
- `author_getMuRaUrl` (no params): Retrieves the mutual remote attestation url of the worker (Only needed by fellow validateers).
- `author_getUntrustedUrl` (no params): Retrieves the untrusted ws url of the worker (Only needed by fellow validateers).

# Sidechain
- `author_submitAndWatchExtrinsic`, params: `Vec<u8>`, which is an substrate codec encoded request. Structure:
    -  [Request](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/core-primitives/types/src/lib.rs#L64-L68):
         - shard :  `H256` : H256 hash of a state
         - cyphertext : `Vec<u8>` : encrypted `TrustedOperation` (with the shielding key).
    - [`TrusetdOperation`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L112-L118): May be a indirect / direct TrustedCallSigned or a Getter.
        - [`Getter`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L144-L149) may be trusted or public.
        A trusted getter must be signed: [`TrustedGetterSigned`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L227-L231). The [Getter](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L204-L210) itself may be further expanded according to the users need (see https://book.integritee.network/howto_stf.html).
        With a getter the following gets are supported:
            - `free_balance` of an account.
            - `reservered_balance` of an account.
            - `nonce` of an account.
        - [`TrustedCallSigned`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L243-L248) contains the following:
            - nonce
            - [signature](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L195-L200) of the call (contains the nonce, mrenclave as well as the shard)
            - the [`TrustedCall`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/app-libs/stf/src/lib.rs#L169-L176)
        The current `TrustedCall` supports the following calls:
            - `balance_set_balance` set the balance of an account (signer, beneficary, free balance, reserved balance)
            - `balance_transfer` transfer balance from first account to second account
            - `balance_unshield` transfer balance from sidechain (incognito) account to parentchain (public) account.
            - `balance_shield` transfer balance from parentchain (public) account to sidechain (incognito) account.

## Response
The server response is a json rpc response containing an substrate codec encoded [`RpcReturnValue`](https://github.com/integritee-network/worker/blob/17e9776cbf09d0a1dd765546f27fc4d3c7bfefc4/core-primitives/types/src/rpc.rs#L8-L14)
