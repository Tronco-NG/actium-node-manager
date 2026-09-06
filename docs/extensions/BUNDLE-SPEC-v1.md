# `actium-product-extension-bundle@1.0.0`

The stable filesystem form is a directory named by convention
`*.actium-extension`:

```text
manifest.json
artifacts/<product>/<capability files>
contracts/<optional neutral contracts>
metadata/<producer metadata>
```

The filename is not trusted. Identity is the manifest digest plus the signed
manifest. The manifest has `schema: 1`, `bundle_id`, `product`,
`bundle_version`, `platform`, `architecture`, capability descriptors,
artifact `{path, sha256, size}` records, dependencies, compatibility,
`issued_at`, optional `expires_at`, `manifest_digest` and Ed25519 signing
metadata `{key_id, algorithm, signature}`.

All artifact paths are relative `artifacts/...` paths. Absolute paths,
parent traversal, backslashes, duplicate paths, symlinks, missing files, size
or digest mismatches and unexpected schemas are rejected. Platform and
architecture may be `any`, otherwise they must match the running host.

The signature covers the lowercase hexadecimal SHA-256 digest of the canonical
manifest with `manifest_digest` and `signing.signature` blanked. Artifacts are
verified independently. No deployment identity, secret or endpoint belongs in
the bundle.
