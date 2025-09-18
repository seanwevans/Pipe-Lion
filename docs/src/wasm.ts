export type PacketProcessor = {
  process_packet: (data: Uint8Array) => string;
};

let cachedProcessor: PacketProcessor | null = null;
let loadPromise: Promise<PacketProcessor> | null = null;

const baseUrl = import.meta.env.BASE_URL ?? "/";

const resolveOrigin = (): string => {
  if (typeof window !== "undefined" && window.location) {
    return window.location.origin;
  }

  const nodeProcess = (globalThis as {
    process?: { env?: Record<string, string | undefined> };
  }).process;

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

const wasmPath = resolveAssetUrl("./pkg/core_bg.wasm");
const wasmModule = resolveAssetUrl("./pkg/core.js");
const wasmModulePath = wasmModule.href;
const wasmBinaryPath = wasmPath.href;

type InitFn = (
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
) => Promise<unknown>;

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
        cachedProcessor = { process_packet: module.process_packet };
        return cachedProcessor;
      } catch (error) {
        loadPromise = null;
        throw error;
      }
    })();
  }

  return loadPromise;
}
