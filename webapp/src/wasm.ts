export type PacketProcessor = {
  process_packet: (data: Uint8Array) => string
}

let cachedProcessor: PacketProcessor | null = null
let loadPromise: Promise<PacketProcessor> | null = null

const wasmPath = new URL('pkg/core_bg.wasm', import.meta.env.BASE_URL)
const wasmModule = new URL('pkg/core.js', import.meta.env.BASE_URL)

type InitFn = (
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
) => Promise<unknown>

export async function loadProcessor(): Promise<PacketProcessor> {
  if (cachedProcessor) {
    return cachedProcessor
  }


  if (!loadPromise) {
    loadPromise = (async () => {
      try {
        const module = (await import(/* @vite-ignore */ wasmModule)) as {
          default: InitFn
          process_packet: (data: Uint8Array) => string
        }

        await module.default(wasmPath)
        cachedProcessor = { process_packet: module.process_packet }
        return cachedProcessor
      } catch (error) {
        loadPromise = null
        throw error
      }
    })()
  }

  return loadPromise

}
