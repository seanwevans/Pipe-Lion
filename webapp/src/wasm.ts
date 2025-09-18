export type PacketProcessor = {
  process_packet: (data: Uint8Array) => string;
};

let cachedProcessor: PacketProcessor | null = null;
let loadPromise: Promise<PacketProcessor> | null = null;


const baseUrl = import.meta.env.BASE_URL ?? "/";
const absoluteBaseUrl =
  typeof window !== "undefined" && window.location
    ? new URL(baseUrl, window.location.origin).toString()
    : baseUrl;

const resolveAssetUrl = (path: string): string => {
  const resolved = new URL(path, absoluteBaseUrl).toString();

  if (import.meta.env.DEV) {
    console.debug(`[wasm] Resolved ${path} to ${resolved}`);
  }

  return resolved;
};

const wasmPath = resolveAssetUrl("./pkg/core_bg.wasm");
const wasmModule = resolveAssetUrl("./pkg/core.js");


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
        const module = (await import(/* @vite-ignore */ wasmModule)) as {
          default: InitFn;
          process_packet: (data: Uint8Array) => string;
        };

        await module.default(wasmPath);
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
