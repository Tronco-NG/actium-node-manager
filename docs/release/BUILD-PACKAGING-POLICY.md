# Windows packaging policy

Node Manager release identity remains `0.7.0-rc.3` until a functional release
change justifies a version bump. The current prerelease toolchain accepts NSIS
for RC builds; MSI is reserved for stable semver builds. M2.2 therefore does
not alter semver to satisfy MSI.

Base Runtime builds are universal and contain no Aegis `PAYLOAD.json`. Aegis
capabilities are packaged separately as a signed Product Extension Bundle v1.
Diagnostics must expose version, `source_commit`, `build_id` and
`binary_sha256`.
