# did:cid through Affinidi's DIDComm stack

Proof (2026-10-22) that Affinidi's maintained DIDComm engine (`affinidi-messaging-didcomm` 0.15.11)
and resolver SDK (`affinidi-did-resolver-cache-sdk` 0.8.43) can message an Archon `did:cid` agent
with no change to Affinidi code: a did:cid resolver is registered through the SDK's public
`DIDCacheClient::set_resolver` plug-in point and delegates to any universal-resolver-compatible
endpoint (`<base>/1.0/identifiers/<did>`; default https://dev.uniresolver.io).

Result: authcrypt (ECDH-1PU+A256KW / A256CBC-HS512) from a did:peer:2 sender, POSTed to the
published `DIDCommMessaging` uri as-is, received and unpacked by GenitriX (`archon_receive_didcomm`),
`metadata.authenticated: true`, sender = the did:peer:2 `#key-1`.

Build needs rustc >= 1.95 (`rustup toolchain install stable`, then
`~/.rustup/toolchains/stable-*/bin/cargo build`; Homebrew's 1.94 is too old).

    ./target/debug/didcid-affinidi-harness <did:cid> [--post]     # RESOLVER_BASE overrides the resolver

Notes for a real driver: Affinidi's `Document` types `verificationMethod[].id` as `url::Url`, so
relative ids ("#key-1", which DID Core allows and Archon uses for the control key) must be made
absolute by the resolver; the SDK also normalises service `type` to an array.
