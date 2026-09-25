export const WORKLOAD_PROFILE_SCHEMA = "actium-workload-profile@1.0.0" as const;
export const WORKLOAD_DEPLOYMENT_SCHEMA = "actium-workload-deployment@1.0.0" as const;
export const DESIRED_WORKLOAD_STATE_SCHEMA = "actium-desired-workload-state@1.0.0" as const;
export const WORKLOAD_RECEIPT_SCHEMA = "actium-workload-deployment-receipt@1.0.0" as const;
export const WORKLOAD_DIGEST_VECTORS_SCHEMA = "actium-workload-digest-vectors@1.0.0" as const;

export const RUNTIME_READINESS = [
  "DECLARED_BY_CONTRACT",
  "RUNTIME_AVAILABLE",
  "RESERVED",
] as const;
export type RuntimeReadiness = (typeof RUNTIME_READINESS)[number];

export const SUPPORTED_RUNTIME_KINDS = ["OCI_CONTAINER", "OCI_COMPOSE"] as const;
export const IMPLEMENTED_RUNTIME_KINDS = SUPPORTED_RUNTIME_KINDS;
export const RESERVED_RUNTIME_KINDS = ["VM"] as const;
export const RUNTIME_KINDS = [...SUPPORTED_RUNTIME_KINDS, ...RESERVED_RUNTIME_KINDS] as const;
export type RuntimeKind = (typeof RUNTIME_KINDS)[number];

export const NETWORK_POLICIES = [
  "ISOLATED",
  "SITE_INTERNAL",
  "PRODUCT_INTERNAL",
  "PUBLIC_HTTPS",
] as const;
export type NetworkPolicy = (typeof NETWORK_POLICIES)[number];

export const CONVERGENCE_PHASES = [
  "DESIRED",
  "PLAN",
  "PREPARE",
  "INSTALL",
  "START",
  "HEALTH",
  "READY",
  "ROLLBACK",
] as const;
export type ConvergencePhase = (typeof CONVERGENCE_PHASES)[number];

export const COMPONENT_STATUSES = ["PENDING", "READY", "DEGRADED", "FAILED", "STOPPED"] as const;
export type ComponentStatus = (typeof COMPONENT_STATUSES)[number];

export function runtimeReadiness(kind: RuntimeKind, executorAvailable = false): RuntimeReadiness {
  if (kind === "VM") return "RESERVED";
  return executorAvailable ? "RUNTIME_AVAILABLE" : "DECLARED_BY_CONTRACT";
}

export function isSupportedRuntimeKind(kind: string): boolean {
  return (SUPPORTED_RUNTIME_KINDS as readonly string[]).includes(kind);
}
export const isImplementedRuntimeKind = isSupportedRuntimeKind;

export function profileHasInlineSecretValues(profile: unknown): boolean {
  const json = JSON.stringify(profile);
  return /"(password|secret|api[_-]?key|app_key)"\s*:\s*"[^"]+"/i.test(json);
}

export function overallFromComponents(
  components: ReadonlyArray<{ status: ComponentStatus }>,
): ComponentStatus {
  if (components.length === 0) return "FAILED";
  if (components.every((component) => component.status === "READY")) return "READY";
  if (components.some((component) => component.status === "FAILED")) return "FAILED";
  if (components.every((component) => component.status === "STOPPED")) return "STOPPED";
  if (components.some((component) => component.status === "DEGRADED")) return "DEGRADED";
  return "PENDING";
}

export function nativeCapabilitiesRemainClosedList(): true {
  return true;
}
