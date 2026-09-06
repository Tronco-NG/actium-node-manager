# KeyProvider

The stable interface is `generate`, `load`, `sign`, `public_key`,
`fingerprint`, `rotate` and `revoke`. Callers receive `KeyDescriptor`, never
private bytes.

`TestEphemeralKeyProvider` exists only in tests/local ceremony fixtures.
`SoftwareSealedKeyProvider` stores an `ACTIUM-SEALED-KEY-V1` AES-256-GCM
ciphertext and a separate revocation marker. The sealing key is supplied by a
future Authority Service/OS keystore and is not persisted by this provider.
No PEM private key is logged, serialized or returned through IPC.
