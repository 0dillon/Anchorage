# Anchorage

Anchorage is a SEP-10 authentication server for Stellar, written in Go.

SEP-10 is Stellar Web Authentication: a challenge-response protocol proving a user controls a Stellar account, without a password. The server issues an unsubmitted transaction, the client signs it, the server verifies the signatures and returns a JWT.

It is the prerequisite layer beneath SEP-6, SEP-24, and SEP-31. Every anchor, wallet backend, and on/off-ramp on Stellar depends on it.

Reference server implementations exist in Python (django-polaris), PHP (Argo Navis SDK), and Java (SDF's Anchor Platform). Go — the language of Horizon, stellar-rpc, and SDF's own SDK — has the protocol primitives and no server around them.

**Scope Boundary:** This is the authentication layer only. It is not an anchor, not KYC, and not deposit and withdrawal. Those systems are built on top of it.

## Next steps

* [What SEP-10 is](concepts.md)
* [Architecture](architecture.md)
* [Deployment](deployment.md)
* [Anchorage GitHub Repository](https://github.com/0dillon/Anchorage)
