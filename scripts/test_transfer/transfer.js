// Import the API & Provider and some utility functions
const { ApiPromise } = require('@polkadot/api');

const { Keyring } = require('@polkadot/keyring');

// Utility function for random values
const { randomAsU8a } = require('@polkadot/util-crypto');

// Some constants we are using in this sample
const AMOUNT = 1000000000000;

async function main () {
    // Create the API and wait until ready
    const api = await ApiPromise.create();

    // Create an instance of a testing keyring
    const keyring = new Keyring({ type: 'sr25519', ss58Format: 42 });
    const alice = keyring.addFromUri('//Alice');

    // Access the publicKey and address
    const { publicKey, address } = alice;

    console.log('Alice Public Key:', publicKey);
    console.log('Alice Address:', address);

    const { nonce, data: balance } = await api.query.system.account(publicKey);

    // Create a new random recipient
    const recipient = keyring.addFromSeed(randomAsU8a(32)).address;

    console.log('Sending', AMOUNT, 'from', address, 'who has a balance of', balance.free, 'to', recipient, 'with nonce', nonce.toString());

    api.tx.balances
        .transfer(recipient, AMOUNT)
        .signAndSend(alice, { nonce }, ({ events = [], status }) => {
        console.log('Transaction status:', status.type);

        if (status.isInBlock) {
            console.log('Included at block hash', status.asInBlock.toHex());
            console.log('Events:');

            events.forEach(({ event: { data, method, section }, phase }) => {
            console.log('\t', phase.toString(), `: ${section}.${method}`, data.toString());
            });
        } else if (status.isFinalized) {
            console.log('Finalized block hash', status.asFinalized.toHex());

            process.exit(0);
        }
        });
}

main().catch(console.error);
