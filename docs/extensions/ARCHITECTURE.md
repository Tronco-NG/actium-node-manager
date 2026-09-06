# Product Extension Bundle v1

Actium Node Manager is a universal Base Runtime. Product capabilities arrive as
signed, runtime-installed bundles; they are not compiled into Manager and are
not discovered from Aegis, `resources/node` or `PAYLOAD.json`.

```text
bundle directory
  -> parse/schema/compatibility
  -> manifest signature
  -> artifact digests
  -> staging
  -> preflight
  -> atomic installed version
  -> Supervisor activation
  -> health
  -> durable registry + active marker
```

The local/manual import and the future Center Desired State path use the same
Node Core installation engine. Supervisor owns privileged lifecycle actions;
the Tauri UI only requests them over versioned IPC.

The registry is rooted at the Supervisor-owned `extensions/` directory and
contains `staging/`, `installed/`, `active/`, `rollback/` and the atomic
`registry.json`. Public extension trust records are kept separately under the
Supervisor-owned `extension-trust/` directory; private signing material is
never part of the runtime registry. An empty registry is a valid
`BASE_RUNTIME_READY` + `NO_EXTENSIONS` state.

Bundles identify product/version/platform/architecture only. Client,
Organization, Site and Host assignment remains signed runtime desired state.
