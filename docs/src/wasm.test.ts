import { describe, expect, it, vi } from "vitest";

describe("resolveAssetUrl", () => {
  it("creates a URL when window is unavailable", async () => {
    const originalWindow = (globalThis as { window?: unknown }).window;

    Reflect.deleteProperty(globalThis as { window?: unknown }, "window");
    vi.resetModules();

    try {
      const { resolveAssetUrl } = await import("./wasm");
      const url = resolveAssetUrl("./pkg/core.js");

      expect(url).toBeInstanceOf(URL);
      expect(url.href).toContain("/pkg/core.js");
    } finally {
      if (originalWindow !== undefined) {
        (globalThis as { window?: unknown }).window = originalWindow;
      } else {
        Reflect.deleteProperty(globalThis as { window?: unknown }, "window");
      }
      vi.resetModules();
    }
  });
});

describe("loadProcessor", () => {
  it("parses numeric string lengths from Wasm output", async () => {
    const CORE_MODULE_PATH = "http://localhost/pkg/core.js";

    vi.resetModules();
    vi.doMock(CORE_MODULE_PATH, () => ({
      __esModule: true,
      default: vi.fn(async () => undefined),
      process_packet: vi.fn(() =>
        JSON.stringify({
          packets: [
            {
              time: "0.000001",
              source: "src",
              destination: "dst",
              protocol: "TCP",
              length: "64",
              info: "mock",
              payload: [1, 2, 3],
            },
          ],
          warnings: [],
          errors: [],
        }),
      ),
    }));

    const { loadProcessor } = await import("./wasm");
    const processor = await loadProcessor();
    const result = processor.process_packet(new Uint8Array());

    expect(result.packets).toHaveLength(1);
    expect(result.packets[0]?.length).toBe(64);

    vi.doUnmock(CORE_MODULE_PATH);
    vi.resetModules();
  });
});
