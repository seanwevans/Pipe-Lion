import type { PacketRecord as FilterPacketRecord } from "./filter";

/// One row of the packet list. Payload bytes are deliberately absent: fetch
/// them a packet at a time with `CaptureSession.payload`.
export interface PacketRecord extends FilterPacketRecord {
  index: number;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  hex_preview: string;
  ascii_preview: string;
  payload_length: number;
  layers?: DecodedLayers;
}

/// A row with its bytes attached, for consumers that need them (the exporters).
export interface PacketWithPayload extends PacketRecord {
  payload: Uint8Array;
}

export interface DnsQuestion {
  name: string;
  qtype: string;
  qclass: string;
}

export interface DnsLayer {
  id: number;
  is_response: boolean;
  truncated: boolean;
  opcode: string;
  rcode: string;
  question_count: number;
  answer_count: number;
  authority_count: number;
  additional_count: number;
  questions: DnsQuestion[];
}

export interface TlsClientHello {
  version: string;
  server_name: string | null;
  alpn: string[];
}

export interface TlsLayer {
  content_type: string;
  version: string;
  handshake_type: string | null;
  client_hello: TlsClientHello | null;
}

export interface DecodedLayers {
  ethernet?: { source_mac: string; destination_mac: string; ethertype: number };
  ipv4?: { source: string; destination: string; protocol: number };
  ipv6?: { source: string; destination: string; next_header: number };
  tcp?: {
    source_port: number;
    destination_port: number;
    header_length: number;
  };
  udp?: { source_port: number; destination_port: number; length: number };
  icmp?: {
    icmp_type: number;
    icmp_code: number;
    description: string;
    version: string;
  };
  dns?: DnsLayer;
  tls?: TlsLayer;
}

/// A parsed capture living in Wasm linear memory.
///
/// Rows cross the boundary a window at a time and payloads one packet at a
/// time, so nothing here is proportional to the size of the capture. Call
/// `free()` when finished — the bytes are not garbage collected.
export interface CaptureSession {
  readonly packetCount: number;
  readonly warnings: string[];
  readonly errors: string[];
  packets: (offset: number, count: number) => PacketRecord[];
  payload: (index: number) => Uint8Array;
  free: () => void;
}

export type PacketProcessor = {
  parse: (data: Uint8Array) => CaptureSession;
};

/// The shape wasm-bindgen generates for `CaptureHandle`.
type WasmCaptureHandle = {
  readonly packet_count: number;
  readonly warnings: string[];
  readonly errors: string[];
  packets: (offset: number, count: number) => string;
  payload: (index: number) => Uint8Array | undefined;
  free: () => void;
};

let cachedProcessor: PacketProcessor | null = null;
let loadPromise: Promise<PacketProcessor> | null = null;

const baseUrl = import.meta.env.BASE_URL ?? "/";

const resolveOrigin = (): string => {
  if (typeof window !== "undefined" && window.location) {
    return window.location.origin;
  }

  const nodeProcess = (
    globalThis as {
      process?: { env?: Record<string, string | undefined> };
    }
  ).process;

  return nodeProcess?.env?.DOCS_ORIGIN ?? "http://localhost";
};

const absoluteBaseUrl = new URL(baseUrl, resolveOrigin());

export const resolveAssetUrl = (path: string): URL => {
  const resolved = new URL(path, absoluteBaseUrl);

  if (import.meta.env.DEV) {
    console.debug(`[wasm] Resolved ${path} to ${resolved.href}`);
  }

  return resolved;
};

const wasmBinaryUrl = resolveAssetUrl("./pkg/core_bg.wasm");
const wasmModuleUrl = resolveAssetUrl("./pkg/core.js");
const wasmModulePath = wasmModuleUrl.href;
const wasmBinaryPath = wasmBinaryUrl.href;

type InitFn = (
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
) => Promise<unknown>;

const toStringOrFallback = (value: unknown, fallback: string): string => {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length > 0) {
      return trimmed;
    }
  }
  return fallback;
};

const toFiniteNumberOrFallback = (value: unknown, fallback: number): number => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length > 0) {
      const parsed = Number(trimmed);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }

  return fallback;
};

const toLayers = (value: unknown): DecodedLayers | undefined =>
  typeof value === "object" && value !== null
    ? (value as DecodedLayers)
    : undefined;

const toRecord = (
  value: unknown,
  fallbackIndex: number,
): PacketRecord | null => {
  if (typeof value !== "object" || value === null) {
    return null;
  }

  const row = value as Record<string, unknown>;
  const length = Math.max(
    0,
    Math.round(toFiniteNumberOrFallback(row.length, 0)),
  );

  return {
    index: Math.max(
      0,
      Math.round(toFiniteNumberOrFallback(row.index, fallbackIndex)),
    ),
    time: toStringOrFallback(row.time, "0.000000"),
    source: toStringOrFallback(row.source, "—"),
    destination: toStringOrFallback(row.destination, "—"),
    protocol: toStringOrFallback(row.protocol, "—"),
    length,
    info: toStringOrFallback(row.info, "—"),
    hex_preview: toStringOrFallback(row.hex_preview, ""),
    ascii_preview: toStringOrFallback(row.ascii_preview, ""),
    payload_length: Math.max(
      0,
      Math.round(toFiniteNumberOrFallback(row.payload_length, length)),
    ),
    layers: toLayers(row.layers),
  };
};

const parsePacketRows = (raw: string, offset: number): PacketRecord[] => {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .map((row, position) => toRecord(row, offset + position))
      .filter((row): row is PacketRecord => row !== null);
  } catch (error) {
    if (import.meta.env.DEV) {
      console.debug("[wasm] Failed to parse packet window", error);
    }
    return [];
  }
};

const toSession = (handle: WasmCaptureHandle): CaptureSession => ({
  get packetCount() {
    return handle.packet_count;
  },
  get warnings() {
    return [...handle.warnings];
  },
  get errors() {
    return [...handle.errors];
  },
  packets: (offset: number, count: number) =>
    count <= 0 ? [] : parsePacketRows(handle.packets(offset, count), offset),
  payload: (index: number) => handle.payload(index) ?? new Uint8Array(),
  free: () => handle.free(),
});

export async function loadProcessor(): Promise<PacketProcessor> {
  if (cachedProcessor) {
    return cachedProcessor;
  }

  if (!loadPromise) {
    loadPromise = (async () => {
      try {
        const module = (await import(/* @vite-ignore */ wasmModulePath)) as {
          default: InitFn;
          parse: (data: Uint8Array) => WasmCaptureHandle;
        };

        await module.default(wasmBinaryPath);
        cachedProcessor = {
          parse: (data: Uint8Array) => toSession(module.parse(data)),
        };
        return cachedProcessor;
      } catch (error) {
        loadPromise = null;
        throw error;
      }
    })();
  }

  return loadPromise;
}
