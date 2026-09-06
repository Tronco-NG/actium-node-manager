# Host Enrollment ceremony v1

The only human input is a single-use `hen_*` ticket. Center derives the complete
scope from possession of that ticket; Manager never asks for client, organization,
site, host, installation or epoch identifiers.

The machine flow is:

`hen_* → challenge → Supervisor PoP → Center complete → pending_apply → EnrollmentPackage → Supervisor apply → signed ACK → Center confirm → enrolled/trusted → signed discovery`

The Supervisor ACK must carry the exact `enrollmentNonce` issued for the ceremony.
Center remains the authority for ticket consumption and final enrollment state.
