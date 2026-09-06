# Actium Node Manager contracts

These are versioned, neutral wire contracts owned by `Tronco-NG/actium-node-manager`.
Consumers must pin a contract name and version; they must not import source files
from this repository or infer a contract from a sibling checkout path.

The base runtime is the universal Manager, Supervisor, Node Core, Host Identity,
enrollment, trust, discovery, storage and diagnostics platform. Product-specific
capabilities are external extension bundles and are never compiled into the base
runtime by client, organization, site or host.

The legacy Aegis `PAYLOAD.json` remains a frozen compatibility artifact owned by
Ecosistema Aegis. It is not a Node Manager source file, contract, or build input.

## Contract policy

- `contract_name` and `contract_version` are mandatory on every top-level document.
- Patch releases are wire-compatible; minor releases require an additive compatibility review.
- Major releases require an explicit adapter and migration gate.
- URLs, IDs, tokens and authority material are runtime state; they are not embedded here.

The `actium-node-manager-host@1.0.0` contract defines the universal base
runtime boundary. Product capabilities cross that boundary only as external,
signed extension bundles; they are not copied into or compiled into the base
runtime.

`actium-product-extension-bundle@1.0.0` is the canonical bundle contract.
Its manifest binds a universal product/version/platform/architecture to
capabilities and individually digested artifacts. Client, Organization, Site,
Host, credentials and deployment endpoints are deliberately outside the
bundle and belong to later signed desired state.
