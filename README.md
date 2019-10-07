# substraTEE-worker
SubstraTEE worker for SubstraTEE node

This is part of [substraTEE](https://github.com/scs/substraTEE)

**Supports Rust nightly-2019-07-15**
 
**Enclave is compiled with nightly-2019-10-03**

## Private-tx demo
To run a demo for private tokens do the following:

Assumptions: 
* your machine has SGX support 
* Intel SGX SDK installed.
* rust toolchain is ready to build substrate

in terminal 1 run a substraTEE-node
```
git clone https://github.com/scs/substraTEE-node
cd substraTEE-node
git checkout tags/M5
cargo build --release
./target/release/substratee-node --dev --ws-port 9979 --rpc-port 9969
```

in terminal 2, run the worker
```
git clone https://github.com/scs/substraTEE-worker
cd substraTEE-worker
git checkout tags/M5
make
cd bin
RUST_LOG=info ./substratee_worker -p 9979 worker
```

in terminal 3, run the client
```
cd substraTEE-worker/bin
./substratee_client --node-ws-port 9979
```

Then you should see this in terminal 3:
```
*** Getting the amount of the registered workers
[<] Found 1  workers

[>] Getting the first worker's from the substraTEE-node
[<] Got first worker's coordinates:
    W1's public key : "5Gkzji8EtE1hTjVzTmZXWqrs6sqcHcbCooGqVH7iRRuxdnar"
    W1's url: "127.0.0.1:2000"

[>] Get the shielding key from W1 (=5Gkzji8EtE1hTjVzTmZXWqrs6sqcHcbCooGqVH7iRRuxdnar)
[<] Got worker shielding key Rsa3072KeyPair: { n:CF67550FB00AB959A76219EA35188B360380037123FCAA77B683A791A1F980331F9D9E11D04C7F5FB3B63787F8AAB579FDFFE1DCE79A29B6ACED2628635C8463965D5D839BD58072AA77B8CAE124E40562955FE9936DAE2976CD57B41A2DE89EEDBF9DA77C155365E8BB45DCA1E0EC3B32604D9489712762BE63B3D1F04801D796887F70115BFDD440450A04BFE81DEE7BE718F56F766E6B0C2D9DE270583C4DFBA64FD59B4DE39C07977F1FD2956588DDBF73987EECB5BB303AF2115C4E72879C5EC69B7CD5C00DAEF9F9B062B40ADA16984C574246C8AB882A79D2E1C2F597C1017FBA69D7449BAD85ADE822D92A775DB1766F21C886E762C3E260390B72C82515F1D48FD190059B419C639E3688BCC2070E9CDB6BDDD49202B7296EA2AB01EA2D3AC2990C5078446582A4C03194BBF8D7E557B4503FF4645C053D7288398C79781F642F3A8D399195E6D2E6F74B434791D881BC97BAA0F0B228BD031C40E357BC61644E68CC40F3E08BDCBBD92E306FA9353FAEA05FDCBFCF4729FECC008C, e:01000001 }

[+] Alice's Incognito Pubkey: 5Dt1Wg85pXGLstt36t6TDdvXXoCtG6zkUL17KkyVaPYSrzGH

[+] Bob's Incognito Pubkey: 5GTTq4EnvMk4oTXYJp2kqTd2T9hbnARuee5awLiKFKsxWgRy

[+] pre-funding Alice's Incognito account (ROOT call)
[+] Subscribed, waiting for event...

[+] Received confirm call from 5Gkzji8EtE1hTjVzTmZXWqrs6sqcHcbCooGqVH7iRRuxdnar
[+] query Alice's Incognito account balance
    got getter response from worker: Ok("State is 1000000")
[+] query Bob's Incognito account balance
    got getter response from worker: Ok("State is 0")

*** incognito transfer from Alice to Bob

[+] Subscribed, waiting for event...

[+] Received confirm call from 5Gkzji8EtE1hTjVzTmZXWqrs6sqcHcbCooGqVH7iRRuxdnar
[+] query Alice's Incognito account balance
    got getter response from worker: Ok("State is 900000")
[+] query Bob's Incognito account balance
    got getter response from worker: Ok("State is 100000")

```

### So, what happens here?

Alice wants to transfer 100k tokens privately to Bob. She doesn't use her substraTEE-node account for this as the transfer would be publicly visible.

Instead, she creates an *incognito* account and she keeps her account secret (also the public key). This account will never hit the substraTEE-node blockchain transparently.

The *Demo God* then gives Alice some initial Balance of 1M.

Bob also creates an *incognito* account and tells Alice (and only her) his public key.

Alice now uses SubstraTEE's *shielded transaction* feature to send 100k to Bob.

### under the hood

TODO:
* block diagram
* sequence diagram
