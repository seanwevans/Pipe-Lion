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

  it("uses the Info text the core produced instead of rebuilding it", async () => {
    const CORE_MODULE_PATH = "http://localhost/pkg/core.js";
    const info =
      "DNS 10.0.0.5:51234 \u2192 1.1.1.1:53 Standard query 0x1a2b A example.com";

    vi.resetModules();
    vi.doMock(CORE_MODULE_PATH, () => ({
      __esModule: true,
      default: vi.fn(async () => undefined),
      process_packet: vi.fn(() =>
        JSON.stringify({
          packets: [
            {
              time: "1.000000",
              source: "10.0.0.5:51234",
              destination: "1.1.1.1:53",
              protocol: "DNS",
              length: 74,
              info,
              payload: [],
              layers: {
                ipv4: {
                  source: "10.0.0.5",
                  destination: "1.1.1.1",
                  protocol: 17,
                },
                udp: {
                  source_port: 51234,
                  destination_port: 53,
                  length: 54,
                },
                dns: {
                  id: 6699,
                  is_response: false,
                  truncated: false,
                  opcode: "Standard query",
                  rcode: "No error",
                  question_count: 1,
                  answer_count: 0,
                  authority_count: 0,
                  additional_count: 0,
                  questions: [
                    { name: "example.com", qtype: "A", qclass: "IN" },
                  ],
                },
              },
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

    expect(result.packets[0]?.info).toBe(info);
    expect(result.packets[0]?.protocol).toBe("DNS");
    expect(result.packets[0]?.layers?.dns?.questions[0]?.name).toBe(
      "example.com",
    );

    vi.doUnmock(CORE_MODULE_PATH);
    vi.resetModules();
  });
});
