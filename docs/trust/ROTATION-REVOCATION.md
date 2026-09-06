# Rotation and revocation

Authority rotation is explicit. The old key remains usable only long enough
to co-sign a versioned root transition with the new key; retirement/revocation
is a separate operation. Trust bundles contain the active public set and
revocations.

Supervisors reject a trust epoch below their current epoch. At the same epoch
they accept a bundle only when its digest is identical. A revoked authority,
key or host identity fails closed.
