/**
 * Versioned Center transport for storage discovery/intents.
 *
 * The Manager never manufactures an owner approval. Callers must provide a
 * signed envelope produced by the Supervisor/host trust boundary and this
 * client rejects an unconfigured or unsafe endpoint before any request.
 */
export const STORAGE_TRANSPORT_PROTOCOL = "actium.storage.transport" as const;
export const STORAGE_TRANSPORT_VERSION = 1 as const;
export const STORAGE_TRANSPORT_MAX_TTL_SECONDS = 600;

export type StorageTransportMessageType =
  | "discovery_snapshot"
  | "storage_grant_intent"
  | "storage_grant_approval";

export type StorageTransportScope = {
  clientId: string;
  organizationId: string;
  siteId: string;
  hostId: string;
  hostInstallationId: string;
  deploymentId?: string;
  capability?: string;
};

export type SignedStorageTransport<T> = {
  protocol: typeof STORAGE_TRANSPORT_PROTOCOL;
  version: typeof STORAGE_TRANSPORT_VERSION;
  messageType: StorageTransportMessageType;
  messageId: string;
  idempotencyKey: string;
  issuedAt: number;
  expiresAt: number;
  scope: StorageTransportScope;
  payload: T;
  signerKeyId: string;
  signature: string;
};

export type StorageDiscoveryMount = {
  mountpoint: string;
  source: string;
  filesystem: string;
  filesystemUuid?: string | null;
  label?: string | null;
  totalBytes: number;
  freeBytes: number;
  readOnly: boolean;
  isRoot: boolean;
};

export type StorageDiscoverySnapshot = {
  clientId: string;
  organizationId: string;
  siteId: string;
  hostId: string;
  hostInstallationId: string;
  reportGeneration: number;
  observedAt: number;
  snapshotHash: string;
  mounts: StorageDiscoveryMount[];
  idempotencyKey: string;
};

export type StorageGrantIntent = {
  intentId: string;
  clientId: string;
  organizationId: string;
  siteId: string;
  hostId: string;
  hostInstallationId: string;
  deploymentId: string;
  capability: string;
  canonicalMountpoint: string;
  subpath: string;
  canonicalPath: string;
  filesystem: string;
  filesystemUuid: string;
  policyHash: string;
  bindingEpoch: number;
  issuedAt: number;
  expiresAt: number;
  idempotencyKey: string;
};

export type StorageApprovalEnvelope = {
  envelope: SignedStorageTransport<StorageGrantIntent>;
  approval: { payload: string; signature: string };
  token: string;
};

export class StorageTransportError extends Error {
  readonly code: string;

  constructor(code: string, message = code) {
    super(message);
    this.code = code;
    this.name = "StorageTransportError";
  }
}

export function canonicalStorageTransportJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStorageTransportJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalStorageTransportJson(record[key])}`).join(",")}}`;
}

export function validateStorageTransportEnvelope<T>(
  envelope: SignedStorageTransport<T>,
  now = Math.floor(Date.now() / 1000),
): void {
  if (!envelope || envelope.protocol !== STORAGE_TRANSPORT_PROTOCOL || envelope.version !== STORAGE_TRANSPORT_VERSION) {
    throw new StorageTransportError("STORAGE_TRANSPORT_VERSION_UNSUPPORTED");
  }
  if (!["discovery_snapshot", "storage_grant_intent", "storage_grant_approval"].includes(envelope.messageType)) {
    throw new StorageTransportError("STORAGE_TRANSPORT_MESSAGE_UNSUPPORTED");
  }
  if (!envelope.messageId || !envelope.idempotencyKey || !envelope.signerKeyId || !envelope.signature) {
    throw new StorageTransportError("STORAGE_TRANSPORT_SIGNATURE_REQUIRED");
  }
  if (!Number.isSafeInteger(envelope.issuedAt) || !Number.isSafeInteger(envelope.expiresAt)
    || envelope.expiresAt <= envelope.issuedAt
    || envelope.expiresAt > envelope.issuedAt + STORAGE_TRANSPORT_MAX_TTL_SECONDS
    || envelope.issuedAt > now + 30
    || now > envelope.expiresAt) {
    throw new StorageTransportError("STORAGE_TRANSPORT_EXPIRED");
  }
  const scope = envelope.scope;
  if (!scope || [scope.clientId, scope.organizationId, scope.siteId, scope.hostId, scope.hostInstallationId]
    .some((value) => typeof value !== "string" || value.trim() === "")) {
    throw new StorageTransportError("STORAGE_TRANSPORT_SCOPE_INVALID");
  }
  if (envelope.messageType !== "discovery_snapshot" && (!scope.deploymentId || !scope.capability)) {
    throw new StorageTransportError("STORAGE_TRANSPORT_SCOPE_INVALID");
  }
  if (envelope.payload === null || typeof envelope.payload !== "object") {
    throw new StorageTransportError("STORAGE_TRANSPORT_PAYLOAD_INVALID");
  }
}

export function validateCenterStorageTransportUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new StorageTransportError("STORAGE_CENTER_TRANSPORT_URL_INVALID");
  }
  const hostname = parsed.hostname.toLowerCase();
  const loopback = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
  if (parsed.username || parsed.password || (!loopback && parsed.protocol !== "https:") || (loopback && !["http:", "https:"].includes(parsed.protocol))) {
    throw new StorageTransportError("STORAGE_CENTER_TRANSPORT_URL_UNSAFE");
  }
  return parsed.toString().replace(/\/$/, "");
}

export type StorageCenterTransport = {
  publishDiscovery(envelope: SignedStorageTransport<StorageDiscoverySnapshot>): Promise<void>;
  publishIntent(envelope: SignedStorageTransport<StorageGrantIntent>): Promise<{ status: "pending" }>;
  fetchApproval(intentId: string, scope: StorageTransportScope): Promise<StorageApprovalEnvelope>;
};

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export class HttpStorageCenterTransport implements StorageCenterTransport {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly headers: Record<string, string>;

  constructor(rawBaseUrl: string, options: { fetchImpl?: FetchLike; headers?: Record<string, string> } = {}) {
    this.baseUrl = validateCenterStorageTransportUrl(rawBaseUrl);
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.headers = { "content-type": "application/json", ...(options.headers ?? {}) };
  }

  async publishDiscovery(envelope: SignedStorageTransport<StorageDiscoverySnapshot>): Promise<void> {
    validateStorageTransportEnvelope(envelope);
    if (envelope.messageType !== "discovery_snapshot") throw new StorageTransportError("STORAGE_TRANSPORT_MESSAGE_UNSUPPORTED");
    await this.request("/storage/discovery", { method: "POST", body: JSON.stringify(envelope) });
  }

  async publishIntent(envelope: SignedStorageTransport<StorageGrantIntent>): Promise<{ status: "pending" }> {
    validateStorageTransportEnvelope(envelope);
    if (envelope.messageType !== "storage_grant_intent") throw new StorageTransportError("STORAGE_TRANSPORT_MESSAGE_UNSUPPORTED");
    const response = await this.request("/intents", { method: "POST", body: JSON.stringify(envelope) }) as { status?: string };
    if (response.status !== "pending") throw new StorageTransportError("STORAGE_TRANSPORT_RESPONSE_INVALID");
    return { status: "pending" };
  }

  async fetchApproval(intentId: string, scope: StorageTransportScope): Promise<StorageApprovalEnvelope> {
    if (!intentId.trim()) throw new StorageTransportError("STORAGE_INTENT_ID_REQUIRED");
    if (!scope.deploymentId || !scope.capability) throw new StorageTransportError("STORAGE_TRANSPORT_SCOPE_INVALID");
    const response = await this.request(`/intents/${encodeURIComponent(intentId)}/approval`, { method: "GET" }) as StorageApprovalEnvelope;
    validateStorageTransportEnvelope(response.envelope);
    if (response.envelope.messageType !== "storage_grant_approval") throw new StorageTransportError("STORAGE_TRANSPORT_MESSAGE_UNSUPPORTED");
    const approvalScope = response.envelope.scope;
    if (canonicalStorageTransportJson(approvalScope) !== canonicalStorageTransportJson(scope)) {
      throw new StorageTransportError("STORAGE_TRANSPORT_SCOPE_INVALID");
    }
    if (!response.token || !response.approval?.payload || !response.approval.signature) {
      throw new StorageTransportError("STORAGE_APPROVAL_MATERIAL_UNAVAILABLE");
    }
    return response;
  }

  private async request(path: string, init: RequestInit): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, { ...init, headers: { ...this.headers, ...(init.headers ?? {}) } });
    } catch (error) {
      throw new StorageTransportError("STORAGE_CENTER_TRANSPORT_UNAVAILABLE", String(error));
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new StorageTransportError("STORAGE_CENTER_TRANSPORT_RESPONSE_INVALID");
    }
    if (!response.ok) {
      const code = typeof payload === "object" && payload !== null && "code" in payload ? String((payload as { code: unknown }).code) : "STORAGE_CENTER_TRANSPORT_REJECTED";
      throw new StorageTransportError(code);
    }
    return payload;
  }
}
