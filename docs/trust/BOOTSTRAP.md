# First trust bootstrap

The universal build carries only the initial Product Trust public anchor/set.
On a new Host, a signed deployment descriptor is verified against that
anchor, followed by a signed Trust Bundle. The Supervisor installs the
bundle only after signature, chain, validity, revocation and epoch checks.
Only then may Host Enrollment use the Enrollment Authority.

If the Authority Service or chain is unavailable, enrollment remains fail
closed with `HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE` before the ticket is
consumed.

The anchor is not a Center key, and is not scoped to a Client, Organization,
Site or Host. It contains no private material. A missing anchor keeps the
runtime available but returns `TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE` for trust
installation. Root-set changes require a signed dual-root transition; silent
TOFU is not supported.

The Center UI may create an AAL2-protected, non-secret ceremony plan. It does
not generate a root, accept a pasted PEM, or activate an authority. The Owner
must complete the offline custody/recovery decision and provide the verified
public descriptor before the durable service can be considered initialized.
