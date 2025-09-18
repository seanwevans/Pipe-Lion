export type PacketProcessor = {
  process_packet: (data: Uint8Array) => string
}

let cachedProcessor: PacketProcessor | null = null

const wasmPath = '/pkg/core_bg.wasm'
const wasmModule = '/pkg/core.js'

type InitFn = (
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module,
) => Promise<unknown>

export async function loadProcessor(): Promise<PacketProcessor> {
  if (cachedProcessor) {
    return cachedProcessor
  }

  const module = (await import(/* @vite-ignore */ wasmModule)) as {
    default: InitFn
    process_packet: (data: Uint8Array) => string
  }

  await module.default(wasmPath)
  cachedProcessor = { process_packet: module.process_packet }
  return cachedProcessor
}
