import { describe, expect, it, vi } from "vitest";

import type { PacketProcessor } from "./wasm";

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
  const CORE_MODULE_PATH = "http://localhost/pkg/core.js";

  const mockHandle = (rows: unknown[], payloads: Uint8Array[] = []) => ({
    packet_count: rows.length,
    warnings: [] as string[],
    errors: [] as string[],
    packets: vi.fn((offset: number, count: number) =>
      JSON.stringify(rows.slice(offset, offset + count)),
    ),
    payload: vi.fn((index: number) => payloads[index]),
    free: vi.fn(),
  });

  const dnsRow = {
    index: 0,
    time: "1.000000",
    source: "10.0.0.5:51234",
    destination: "1.1.1.1:53",
    protocol: "DNS",
    length: 74,
    info: "DNS 10.0.0.5:51234 \u2192 1.1.1.1:53 Standard query 0x1a2b A example.com",
    hex_preview: "45 00",
    ascii_preview: "E.",
    payload_length: 74,
    layers: {
      ipv4: { source: "10.0.0.5", destination: "1.1.1.1", protocol: 17 },
      udp: { source_port: 51234, destination_port: 53, length: 54 },
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
        questions: [{ name: "example.com", qtype: "A", qclass: "IN" }],
      },
    },
  };

  const withMockedCore = async (
    handle: ReturnType<typeof mockHandle>,
    body: (processor: PacketProcessor) => void,
  ) => {
    vi.resetModules();
    vi.doMock(CORE_MODULE_PATH, () => ({
      __esModule: true,
      default: vi.fn(async () => undefined),
      parse: vi.fn(() => handle),
    }));

    const { loadProcessor } = await import("./wasm");
    body(await loadProcessor());

    vi.doUnmock(CORE_MODULE_PATH);
    vi.resetModules();
  };

  it("decodes a window of packet rows", async () => {
    const handle = mockHandle([dnsRow]);

    await withMockedCore(handle, (processor) => {
      const session = processor.parse(new Uint8Array());

      expect(session.packetCount).toBe(1);
      expect(session.packets(0, 10)).toHaveLength(1);
      expect(handle.packets).toHaveBeenCalledWith(0, 10);
      expect(session.packets(0, 10)[0]?.info).toBe(dnsRow.info);
      expect(session.packets(0, 10)[0]?.protocol).toBe("DNS");
      expect(session.packets(0, 10)[0]?.layers?.dns?.questions[0]?.name).toBe(
        "example.com",
      );
    });
  });

  it("does not call into Wasm for an empty window", async () => {
    const handle = mockHandle([dnsRow]);

    await withMockedCore(handle, (processor) => {
      const session = processor.parse(new Uint8Array());

      expect(session.packets(0, 0)).toEqual([]);
      expect(handle.packets).not.toHaveBeenCalled();
    });
  });

  it("coerces numeric strings and fills in missing row fields", async () => {
    const handle = mockHandle([
      {
        time: "0.000001",
        source: "src",
        destination: "dst",
        protocol: "TCP",
        length: "64",
        info: "mock",
      },
    ]);

    await withMockedCore(handle, (processor) => {
      const [row] = processor.parse(new Uint8Array()).packets(0, 1);

      expect(row?.length).toBe(64);
      expect(row?.index).toBe(0);
      expect(row?.payload_length).toBe(64);
      expect(row?.hex_preview).toBe("");
    });
  });

  it("fetches payloads one packet at a time and frees the capture", async () => {
    const bytes = Uint8Array.from([1, 2, 3]);
    const handle = mockHandle([dnsRow], [bytes]);

    await withMockedCore(handle, (processor) => {
      const session = processor.parse(new Uint8Array());

      expect(session.payload(0)).toEqual(bytes);
      expect(handle.payload).toHaveBeenCalledWith(0);
      // Out of range: an empty buffer, never undefined.
      expect(session.payload(9)).toEqual(new Uint8Array());

      session.free();
      expect(handle.free).toHaveBeenCalledTimes(1);
    });
  });

  it("returns no rows when the window is not valid JSON", async () => {
    const handle = mockHandle([]);
    handle.packet_count = 1;
    handle.packets = vi.fn(() => "not json");

    await withMockedCore(handle, (processor) => {
      expect(processor.parse(new Uint8Array()).packets(0, 1)).toEqual([]);
    });
  });
});
