export const KNOWN_PROFILES = [
  "site-core",
  "telemetry",
  "people",
  "control",
  "radio-control",
  "radio-saf",
  "radio-turn",
  "radio-livekit",
  "observability",
  "connectivity",
] as const;

export type KnownProfile = (typeof KNOWN_PROFILES)[number];

export function normalizeProfileCode(raw: string): string {
  const code = raw.trim().toLowerCase().replace(/_/g, "-");
  if (code === "site-core" || code === "sitecore" || code === "site") return "site-core";
  if (code === "telemetry" || code === "gps" || code === "dvr") return "telemetry";
  if (code === "people") return "people";
  if (code === "control") return "control";
  if (code === "radio" || code === "radio-control" || code === "ht") return "radio-control";
  if (code === "radio-saf" || code === "saf") return "radio-saf";
  if (code === "radio-turn" || code === "turn") return "radio-turn";
  if (code === "radio-livekit" || code === "livekit") return "radio-livekit";
  if (code === "observability" || code === "metrics" || code === "sre") return "observability";
  if (code === "connectivity" || code === "sync") return "connectivity";
  return code;
}

export function isProfileAuthorized(
  profileId: string,
  authorizedProfiles: readonly string[] | undefined | null,
): boolean {
  if (!authorizedProfiles || authorizedProfiles.length === 0) return false;
  const normalizedTarget = normalizeProfileCode(profileId);
  const normalizedAuthorized = new Set(authorizedProfiles.map(normalizeProfileCode));
  return normalizedAuthorized.has(normalizedTarget);
}

const DEPENDENCIES: Record<string, readonly string[]> = {
  connectivity: ["telemetry"],
};

const PROFILE_FIELDS: Record<string, readonly string[]> = {
  "site-core": ["site-core-port", "site-core-public-url", "site-core-data-path"],
  telemetry: [
    "telemetry-port",
    "telemetry-ingress-public-url",
    "telemetry-read-public-url",
    "telemetry-data-path",
    "dvr-media-path",
  ],
  people: ["people-port", "people-resolve-public-url", "people-data-path"],
  control: [
    "control-runtime-port",
    "control-runtime-public-url",
    "control-object-storage-port",
    "control-object-storage-public-url",
    "control-runtime-data-path",
  ],
  "radio-control": ["radio-control-port", "radio-control-public-url", "radio-control-data-path"],
  "radio-saf": ["radio-saf-port", "radio-archive-host-path", "radio-saf-storage-path"],
  observability: [
    "prometheus-port",
    "grafana-port",
    "metrics-public-url",
    "prometheus-data-path",
    "grafana-data-path",
  ],
  "radio-turn": [
    "turn-realm",
    "turn-external-ip",
    "turn-urls",
    "turn-port",
    "turn-tls-port",
    "turn-min-port",
    "turn-max-port",
    "turn-data-path",
  ],
  "radio-livekit": [
    "livekit-node-ip",
    "livekit-public-url",
    "livekit-http-port",
    "livekit-rtc-tcp-port",
    "livekit-udp-min-port",
    "livekit-udp-max-port",
    "livekit-data-path",
  ],
  connectivity: [
    "connectivity-edge-control-url",
    "connectivity-edge-enrollment-token",
    "connectivity-internal-relay-token",
    "connectivity-node-role",
    "connectivity-node-priority",
    "connectivity-pull-limit",
    "connectivity-sync-enabled",
    "connectivity-fallback-order",
    "connectivity-direct-data-plane-fallback-enabled",
    "connectivity-supabase-fallback-enabled",
    "connectivity-spool-path",
  ],
};

const PROFILE_PORT_FIELDS: Record<string, readonly string[]> = {
  "site-core": ["site-core-port"],
  telemetry: ["telemetry-port"],
  people: ["people-port"],
  control: ["control-runtime-port", "control-object-storage-port"],
  "radio-control": ["radio-control-port"],
  "radio-saf": ["radio-saf-port"],
  observability: ["prometheus-port", "grafana-port"],
  "radio-turn": ["turn-port", "turn-tls-port", "turn-min-port", "turn-max-port"],
  "radio-livekit": [
    "livekit-http-port",
    "livekit-rtc-tcp-port",
    "livekit-udp-min-port",
    "livekit-udp-max-port",
  ],
};

export function effectiveProfiles(selected: readonly string[]): string[] {
  const effective = new Set<string>();
  for (const profile of selected) {
    const normalized = normalizeProfileCode(profile);
    if (!(KNOWN_PROFILES as readonly string[]).includes(normalized as KnownProfile)) continue;
    effective.add(normalized);
    for (const dependency of DEPENDENCIES[normalized] ?? []) effective.add(dependency);
  }
  return [...effective];
}

export function fieldBelongsToProfile(fieldId: string, profile: string): boolean {
  const normalized = fieldId.replace(/^config-/, "");
  return (PROFILE_FIELDS[profile] ?? []).includes(normalized);
}

export function visibleFieldIds(selected: readonly string[]): Set<string> {
  const visible = new Set<string>();
  for (const profile of effectiveProfiles(selected)) {
    for (const field of PROFILE_FIELDS[profile] ?? []) {
      visible.add(field);
      visible.add(`config-${field}`);
    }
  }
  return visible;
}

export function visiblePortFieldIds(selected: readonly string[]): string[] {
  const fields: string[] = [];
  for (const profile of effectiveProfiles(selected)) {
    fields.push(...(PROFILE_PORT_FIELDS[profile] ?? []));
  }
  return fields;
}

export function installerMinVersionForProfiles(profiles: readonly string[]): string {
  return profiles.includes("connectivity") ? "0.4.0" : "0.3.0";
}

/** Heavy-data fields relocated by "Aplicar a Tier 3". Identity (node root, site-core, people) stays on the primary disk. */
export const MASS_STORAGE_SUBDIRS: Record<string, string> = {
  "telemetry-data-path": "telemetry",
  "dvr-media-path": "dvr",
  "control-runtime-data-path": "control",
  "radio-control-data-path": "radio-control",
  "radio-saf-storage-path": "radio-saf",
  "radio-archive-host-path": "radio-archive",
  "turn-data-path": "turn",
  "livekit-data-path": "livekit",
  "prometheus-data-path": "prometheus",
  "grafana-data-path": "grafana",
  "connectivity-spool-path": "connectivity",
};

export function massStorageAssignments(base: string, separator: string): Record<string, string> {
  const normalized = base.trim().replace(/[\\/]+$/, "");
  const assignments: Record<string, string> = {};
  if (!normalized) return assignments;
  for (const [field, subdir] of Object.entries(MASS_STORAGE_SUBDIRS)) {
    assignments[field] = `${normalized}${separator}${subdir}`;
  }
  return assignments;
}

export type ProfileCheckbox = {
  value: string;
  disabled: boolean;
  checked: boolean;
};

export function selectAllProfiles(checkboxes: readonly ProfileCheckbox[]): {
  selected: string[];
  refreshRequired: true;
} {
  const selected = checkboxes
    .filter((item) => !item.disabled)
    .map((item) => item.value)
    .filter(Boolean);
  return { selected, refreshRequired: true };
}

