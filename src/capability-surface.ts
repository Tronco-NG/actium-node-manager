export const KNOWN_PROFILES = [
  "site-core",
  "telemetry",
  "people",
  "radio-control",
  "radio-saf",
  "radio-turn",
  "radio-livekit",
  "observability",
  "connectivity",
] as const;

export type KnownProfile = (typeof KNOWN_PROFILES)[number];

const DEPENDENCIES: Record<string, readonly string[]> = {
  connectivity: ["telemetry"],
};

const PROFILE_FIELDS: Record<string, readonly string[]> = {
  "site-core": ["site-core-port", "site-core-public-url"],
  telemetry: ["telemetry-port", "telemetry-ingress-public-url", "telemetry-read-public-url"],
  people: ["people-port", "people-resolve-public-url"],
  "radio-control": ["radio-control-port", "radio-control-public-url"],
  "radio-saf": ["radio-saf-port", "radio-archive-host-path"],
  observability: ["prometheus-port", "grafana-port", "metrics-public-url"],
  "radio-turn": [
    "turn-realm",
    "turn-external-ip",
    "turn-urls",
    "turn-port",
    "turn-tls-port",
    "turn-min-port",
    "turn-max-port",
  ],
  "radio-livekit": [
    "livekit-node-ip",
    "livekit-public-url",
    "livekit-http-port",
    "livekit-rtc-tcp-port",
    "livekit-udp-min-port",
    "livekit-udp-max-port",
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
  ],
};

const PROFILE_PORT_FIELDS: Record<string, readonly string[]> = {
  "site-core": ["site-core-port"],
  telemetry: ["telemetry-port"],
  people: ["people-port"],
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
    if (!(KNOWN_PROFILES as readonly string[]).includes(profile)) continue;
    effective.add(profile);
    for (const dependency of DEPENDENCIES[profile] ?? []) effective.add(dependency);
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
