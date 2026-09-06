# Aegis PAYLOAD → Product Extension Bundle v1

The mapping is semantic, not byte-for-byte. The Aegis producer reads explicit
service source/release artifacts directly and never treats `PAYLOAD.json` as
canonical input.

| Legacy concern | Extension v1 representation | Owner | Transition |
|---|---|---|---|
| `people` service | `aegis.people` capability and digested artifacts | Ecosistema Aegis | Bundle v1 |
| `telemetry` service | `aegis.telemetry` capability and digested artifacts | Ecosistema Aegis | Bundle v1 |
| `radio` service | `aegis.radio` capability and digested artifacts | Ecosistema Aegis | Bundle v1 |
| `site-core` service | `aegis.site-core` capability and digested artifacts | Ecosistema Aegis | Bundle v1 |
| `control-runtime` service | `aegis.control-runtime` capability and digested artifacts | Ecosistema Aegis | Bundle v1 |
| `resources/node/PAYLOAD.json` | no Base Runtime input; frozen compatibility artifact in Aegis | Aegis packaging | Deprecated |
| Client/Site/Host assignment | signed runtime Desired State from Center | Center | Later gate |

Equivalence is functional for Aegis acceptance, not byte-identical to the
legacy snapshot. `LegacyAegisPayloadAdapter` remains explicit-only until the
bundle is accepted and NAS migration is complete.
