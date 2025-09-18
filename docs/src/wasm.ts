export type PacketProcessor = {
  process_packet: (data: Uint8Array) => string;
};

let cachedProcessor: PacketProcessor | null = null;
let loadPromise: Promise<PacketProcessor> | null = null;

const baseUrl = import.meta.env.BASE_URL ?? "/";
const absoluteBaseUrl: string | URL =
  typeof window !== "undefined" && window.location
    ? new URL(baseUrl, window.location.origin)
    : baseUrl;

const resolveAssetUrl = (path: string): URL => {
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
