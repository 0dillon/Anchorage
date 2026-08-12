# What SEP-10 is

A service needs to know a user controls a Stellar account. Asking for a private key is unacceptable. Asking for a password means managing passwords.

The solution: the server builds a transaction that can never be submitted. The transaction carries a sequence number of zero, ensuring the network always rejects it. It contains a ManageData operation naming the server's home domain and carrying a random 48-byte nonce. The server signs it and sends it to the client. The client signs it and sends it back. The server checks the signatures match the account's signers and meet its threshold, then issues a JWT.

Because the transaction cannot be submitted, signing it is safe. Because it carries a nonce and a short expiry, it cannot be replayed. Because the server signed it first, the client can verify the challenge came from the real server.

## Key components

* **Sequence number zero**: Makes the transaction permanently invalid on-chain.
* **Timebounds**: The challenge expires, typically in five minutes.
* **The nonce**: 64 base64 characters decoding to 48 random bytes, unique per challenge.
* **The home domain operation**: Names which service the user is authenticating to, preventing a challenge from one service from being replayed against another.
* **`web_auth_domain`**: Names the domain of the authentication endpoint itself.
* **`client_domain`**: Optionally identifies the wallet application making the request, proven by a signature from that wallet's own signing key.

## Verification paths

If the account does not exist on the network, the challenge must be signed by the account's own master key. If the account does exist, signatures must match the account's signers and meet its medium threshold.
