# Trust Fabric threat model

The design rejects forged issuers, wrong capabilities, wrong deployment,
expired/not-yet-valid descriptors, revoked keys, tampered certificates and
bundles, epoch rollback, same-epoch digest changes, and release signing by
an enrollment authority. The extension runtime remains confined to its
declared paths and cannot replace Supervisor, Node Core, Host Identity or the
trust store.

Legacy `ACTIUM_HOST_ENROLLMENT_*` and `ACTIUM_ROOT_AUTHORITY_PUBLIC_KEY`
values are compatibility bridges only. Their removal condition is M4 plus
NAS acceptance, successful real enrollment and the M5 gate.
