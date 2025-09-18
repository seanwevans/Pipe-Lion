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
