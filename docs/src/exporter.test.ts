import { describe, expect, it } from "vitest";

import { createPacketExport } from "./exporter";
import type { PacketRecord } from "./wasm";

const createSamplePacket = (overrides: Partial<PacketRecord> = {}): PacketRecord => ({
  time: "1.234567",
  source: "192.168.0.1",
  destination: "192.168.0.2",
  protocol: "TCP",
  length: 3,
  info: "Test packet",
  payload: new Uint8Array([0xde, 0xad, 0xbe]),
  ...overrides,
});

describe("createPacketExport", () => {
  it("throws when no packets are provided", () => {
    expect(() => createPacketExport([])).toThrow("No packets available to export.");
  });

  it("creates a JSON blob with base64 payloads", async () => {
    const { blob, format, filename } = createPacketExport([
      createSamplePacket(),
    ]);

    expect(format).toBe("json");
    expect(blob.type).toBe("application/json");
    expect(filename.endsWith(".json")).toBe(true);

    const text = await blob.text();
    const parsed = JSON.parse(text) as {
      packetCount: number;
      packets: Array<{ payload: string; payloadLength: number }>;
    };

    expect(parsed.packetCount).toBe(1);
    expect(parsed.packets).toHaveLength(1);
    expect(parsed.packets[0]?.payload).toBe("3q2+");
    expect(parsed.packets[0]?.payloadLength).toBe(3);
  });

  it("creates a PCAP blob with the correct structure", async () => {
    const packet = createSamplePacket({ time: "2.000001" });
    const { blob, format, filename } = createPacketExport([packet], {
      format: "pcap",
    });

    expect(format).toBe("pcap");
    expect(blob.type).toBe("application/vnd.tcpdump.pcap");
    expect(filename.endsWith(".pcap")).toBe(true);

    const buffer = await blob.arrayBuffer();
    const view = new DataView(buffer);

    expect(view.getUint32(0, true)).toBe(0xa1b2c3d4);
    expect(view.getUint16(4, true)).toBe(2);
    expect(view.getUint16(6, true)).toBe(4);

    const tsSeconds = view.getUint32(24, true);
    const tsMicros = view.getUint32(28, true);
    const includedLength = view.getUint32(32, true);
    const originalLength = view.getUint32(36, true);

    expect(tsSeconds).toBe(2);
    expect(tsMicros).toBe(1);
    expect(includedLength).toBe(packet.payload.length);
    expect(originalLength).toBeGreaterThanOrEqual(packet.payload.length);

    const payload = new Uint8Array(buffer, 40, packet.payload.length);
    expect(Array.from(payload)).toEqual(Array.from(packet.payload));
  });
});
