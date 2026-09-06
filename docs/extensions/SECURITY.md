# Extension security boundary

`ExtensionBundleVerifier` accepts a `key_id`, Ed25519 public trust material,
manifest digest and signature. It rejects unknown or revoked keys, unsupported
algorithms, modified manifests and modified artifacts. Production trust is
expected from Actium Trust Fabric; tests may inject ephemeral keys through the
verifier API.

An extension is confined to its own installed product directory. The engine
does not execute bundle code during import and never allows an extension to
replace Node Core, Supervisor, Host Identity, Trust Store or another product's
bundle. Path traversal, absolute paths, symlinks and duplicate declarations
fail closed. The Base Runtime remains usable when an extension is absent or
degraded.

`LegacyAegisPayloadAdapter` is explicit-only and deprecated. It is not part of
startup and is not a producer input for new bundles. Removal requires Aegis
Extension Bundle v1, equivalent acceptance and NAS migration completion.
