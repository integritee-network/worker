// A simple sample code for common use cases of the Incognitee API

const {IntegriteeWorker} = require("@encointer/worker-api");
const {Keyring} = require("@polkadot/keyring");
const {cryptoWaitReady, mnemonicToMiniSecret} = require("@polkadot/util-crypto");
const {hexToU8a} = require("@polkadot/util");
const bs58 = require("bs58");

// Adjust these for the shard you'd like to use
const INCOGNITEE_SHARD = "5wePd1LYa5M49ghwgZXs55cepKbJKhj5xfzQGfPeMS7d";
const INCOGNITEE_URL = "wss://scv1.paseo.api.incognitee.io:443";

async function main() {

    // Initialize the Incognitee API
    const api = new IntegriteeWorker(INCOGNITEE_URL);

    // Wait for crypto to be ready
    await cryptoWaitReady();

    // PublicGetters need no signature, can be queried by anyone
    const info = await api.parentchainsInfoGetter(INCOGNITEE_SHARD).send();
    console.log("[PublicGetter] Parentchains Info:")
    console.log(info.toHuman());

    const localKeyring = new Keyring({type: "sr25519", ss58Format: 42});
    const account = localKeyring.addFromUri('//Alice', {
        name: 'Alice',
    });

    // Make sure Alice is funded or use your own account instead:
    // 1. visit app.incognitee.io/pas
    // 2. create test account
    // 3. shield PAS to incognitee
    // 4. copy seed from url and insert it below

    // const account = localKeyring.addFromSeed("<seed>");

    // If you want to shield without using our dApp at app.incognitee.io/pas
    const shard_vault = await api.getShardVault()
    console.log("Send PAS to this shard vault on L1 for shielding: " + shard_vault.toString());

    // querying balance needs authentication (privacy!)
    const getter = await api.accountInfoAndSessionProxiesGetter(account, INCOGNITEE_SHARD);

    const response = await getter.send();
    console.log("[TrustedGetter] Account's free balance: " + response.toHuman().account_info.data.free);
    // check if a session proxy has been defined previously
    console.log("[TrustedGetter] Previously defined session proxy?:");
    console.log(response.toHuman().session_proxies[0]);

    // transfer funds privately on L2
    const fingerprint_hex = await api.getFingerprint();
    const fingerprint = bs58.encode(hexToU8a(fingerprint_hex.toString()));
    console.log("[TrustedCall] using enclave fingerprint:" + fingerprint);

    await api.trustedBalanceTransfer(
        account,
        INCOGNITEE_SHARD,
        fingerprint,
        account.address,
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
        100000000,
        "hello world"
    )

    // send a message to someone
    await api.trustedSendNote(
        account,
        INCOGNITEE_SHARD,
        fingerprint,
        account.address,
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
        "Hi Bob"
    )

    // unshield funds to L1
    await api.balanceUnshieldFunds(
        account,
        INCOGNITEE_SHARD,
        fingerprint,
        account.address,
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
        100000000
    )

    // register a session proxy: let delegate sign on behalf of account, but only for non-transfer actions and queries
    const delegateMiniSecret = mnemonicToMiniSecret("secret forest ticket smooth wide mass parent reveal embark impose fiscal company");
    const delegate = localKeyring.addFromSeed(delegateMiniSecret);

    await api.trustedAddSessionProxy(
        account,
        INCOGNITEE_SHARD,
        fingerprint,
        api.createType('SessionProxyRole', 'NonTransfer'),
        delegate.address,
        null,
        delegateMiniSecret
    )

    // now we can query the account balance using the delegate
    const res = await api.getAccountInfo(
        account.address, // we only pass the address here. no need to know the secret
        INCOGNITEE_SHARD,
        {delegate: delegate} // the delegate account will be used for signing
    )
    console.log("Account's free balance fetched using session proxy: " + res.toHuman().data.free);

    // or we can fetch recent messages and tx history for the account
    // first we fetch note buckets info:
    const noteBucketsInfoGetter = await api.noteBucketsInfoGetter(INCOGNITEE_SHARD);
    const noteBuckets = await noteBucketsInfoGetter.send();
    const lastBucket = noteBuckets.toHuman().last.index
    const notesGetter = await api.notesForTrustedGetter(
        account.address,
        lastBucket,
        INCOGNITEE_SHARD,
        {delegate: delegate}
    )
    const notes = await notesGetter.send();
    console.log("Messages and TX history for account:");
    for (const note of notes) {
        if (note.note.isSuccessfulTrustedCall) {
            const call = api.createType(
                "IntegriteeTrustedCall",
                note.note.asSuccessfulTrustedCall,
            );
            console.log("Call: ", call.toHuman());
        }
    }

    // bye bye
    api.closeWs()
}

main();
