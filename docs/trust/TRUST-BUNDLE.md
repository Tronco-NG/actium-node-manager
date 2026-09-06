# Trust Bundle v1

`actium-trust-bundle@1.0.0` contains public Product Root, Deployment, Center,
Enrollment, Release and Product Signing descriptors, revocations, `trust_epoch`
and issuer signature. It contains no private keys, deployment credentials or
customer secrets. Installation is atomic in the Supervisor-owned trust path.

The same verification primitive is used for first-trust bootstrap and future
desired-state distribution; no silent TOFU is permitted.
