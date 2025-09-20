import type { PacketRecord as FilterPacketRecord } from "./filter";

export interface PacketRecord extends FilterPacketRecord {
  time: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  payload: Uint8Array;
}

export interface PacketProcessingResult {
  packets: PacketRecord[];
  warnings: string[];
  errors: string[];
}

export type PacketProcessor = {
  process_packet: (data: Uint8Array) => PacketProcessingResult;
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
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
};

const decodePayload = (value: unknown, fallback: Uint8Array): Uint8Array => {
  if (value instanceof Uint8Array) {
    return value.slice();
  }

  if (Array.isArray(value)) {
    const bytes = value
      .map((item) =>
        typeof item === "number" && Number.isInteger(item)
          ? ((item % 256) + 256) % 256
          : null,
      )
      .filter((item): item is number => item !== null);
    return Uint8Array.from(bytes);
  }

  if (typeof value === "string" && value.length > 0) {
    try {
      if (typeof globalThis.atob === "function") {
        const binary = globalThis.atob(value);
        const output = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
          output[index] = binary.charCodeAt(index) & 0xff;
        }
        return output;
      }

      const bufferCtor = (
        globalThis as {
          Buffer?: {
            from: (input: string, encoding: string) => Uint8Array | number[];
          };
        }
      ).Buffer;
      if (bufferCtor) {
        const bufferValue = bufferCtor.from(value, "base64");
        return bufferValue instanceof Uint8Array
          ? bufferValue
          : new Uint8Array(bufferValue);
      }
    } catch (error) {
      if (import.meta.env.DEV) {
        console.debug("[wasm] Failed to decode base64 payload", error);
      }
    }
  }

  return fallback.slice();
};

const createFallbackResult = (
  summary: string,
  bytes: Uint8Array,
): PacketProcessingResult => {
  if (import.meta.env.DEV) {
    console.debug("[wasm] Using fallback packet processing result");
  }

  if (bytes.length === 0) {
    return {
      packets: [],
      warnings: [],
      errors: [],
    };
  }

  return {
    packets: [
      {
        time: "0.000000",
        source: "—",
        destination: "—",
        protocol: "RAW",
        length: bytes.length,
        info: summary,
        payload: bytes.slice(),
      },
    ],
    warnings: [],
    errors: [],
  };
};

const parseProcessingResult = (
  raw: string,
  bytes: Uint8Array,
): PacketProcessingResult => {
  try {
    const parsed = JSON.parse(raw) as {
      packets?: unknown;
      warnings?: unknown;
      errors?: unknown;
    };

    const errors = Array.isArray(parsed.errors)
      ? parsed.errors.filter((item): item is string => typeof item === "string")
      : [];
    const warnings = Array.isArray(parsed.warnings)
      ? parsed.warnings.filter(
          (item): item is string => typeof item === "string",
        )
      : [];

    const packets = Array.isArray(parsed.packets)
      ? parsed.packets
          .map((packet): PacketRecord | null => {
            if (typeof packet !== "object" || packet === null) {
              return null;
            }

            const record = packet as Record<string, unknown>;
            const payload = decodePayload(record.payload, bytes);
            const fallbackLength =
              payload.length > 0 ? payload.length : bytes.length;

            return {
              time: toStringOrFallback(record.time, "0.000000"),
              source: toStringOrFallback(record.source, "—"),
              destination: toStringOrFallback(record.destination, "—"),
              protocol: toStringOrFallback(record.protocol, "—"),
              length: Math.max(
                0,
                Math.round(
                  toFiniteNumberOrFallback(record.length, fallbackLength),
                ),
              ),
              info: toStringOrFallback(record.info, "—"),
              payload,
            };
          })
          .filter((packet): packet is PacketRecord => packet !== null)
      : [];

    if (packets.length > 0 || warnings.length > 0 || errors.length > 0) {
      return { packets, warnings, errors };
    }
  } catch (error) {
    if (import.meta.env.DEV) {
      console.debug("[wasm] Failed to parse Wasm response", error);
    }
  }

  return createFallbackResult(raw, bytes);
};

export async function loadProcessor(): Promise<PacketProcessor> {
  if (cachedProcessor) {
    return cachedProcessor;
  }

  if (!loadPromise) {
    loadPromise = (async () => {
      try {
        const module = (await import(/* @vite-ignore */ wasmModulePath)) as {
          default: InitFn;
          process_packet: (data: Uint8Array) => string;
        };

        await module.default(wasmBinaryPath);
        cachedProcessor = {
          process_packet: (data: Uint8Array) =>
            parseProcessingResult(module.process_packet(data), data),
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
