import type { PacketRecord } from "./wasm";

export type PacketExportFormat = "json" | "pcap";

export interface PacketExportOptions {
  format?: PacketExportFormat;
  filenamePrefix?: string;
}

export interface PacketExportResult {
  blob: Blob;
  filename: string;
  format: PacketExportFormat;
}

const JSON_MIME_TYPE = "application/json";
const PCAP_MIME_TYPE = "application/vnd.tcpdump.pcap";
const DEFAULT_PREFIX = "packet-export";
const SNAP_LENGTH = 262_144;
const LINKTYPE_ETHERNET = 1;

const toBase64 = (bytes: Uint8Array): string => {
  if (typeof globalThis.btoa === "function") {
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return globalThis.btoa(binary);
  }

  const bufferCtor = (
    globalThis as {
      Buffer?: {
        from: (
          input: Uint8Array | number[],
          encoding?: string,
        ) => {
          toString: (encoding: string) => string;
        };
      };
    }
  ).Buffer;

  if (bufferCtor) {
    return bufferCtor.from(bytes).toString("base64");
  }

  const table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const chunkLength = Math.min(3, bytes.length - index);
    const a = bytes[index] ?? 0;
    const b = bytes[index + 1] ?? 0;
    const c = bytes[index + 2] ?? 0;
    const triplet = (a << 16) | (b << 8) | c;

    const enc1 = (triplet >> 18) & 0x3f;
    const enc2 = (triplet >> 12) & 0x3f;
    const enc3 = (triplet >> 6) & 0x3f;
    const enc4 = triplet & 0x3f;

    output += table[enc1] ?? "";
    output += table[enc2] ?? "";
    output += chunkLength > 1 ? table[enc3] ?? "" : "=";
    output += chunkLength > 2 ? table[enc4] ?? "" : "=";
  }

  return output;
};

const createJsonExport = (
  packets: PacketRecord[],
  filenamePrefix: string,
): PacketExportResult => {
  const payload = {
    generatedAt: new Date().toISOString(),
    packetCount: packets.length,
    packets: packets.map((packet, index) => ({
      index,
      time: packet.time,
      source: packet.source,
      destination: packet.destination,
      protocol: packet.protocol,
      length: packet.length,
      info: packet.info,
      payloadLength: packet.payload.length,
      payload: toBase64(packet.payload),
    })),
  };

  const content = JSON.stringify(payload, null, 2);
  const timestamp = new Date().toISOString().replace(/[:]/g, "-");
  const filename = `${filenamePrefix}-${timestamp}.json`;

  return {
    blob: new Blob([content], { type: JSON_MIME_TYPE }),
    filename,
    format: "json",
  };
};

const parseTimestamp = (
  time: string,
  fallbackIndex: number,
): {
  seconds: number;
  microseconds: number;
} => {
  const numeric = Number(time);
  if (Number.isFinite(numeric) && numeric >= 0) {
    const seconds = Math.floor(numeric);
    const microseconds = Math.round((numeric - seconds) * 1_000_000);
    return { seconds, microseconds };
  }

  const match = /^\s*(\d+)(?:\.(\d{1,6}))?\s*$/.exec(time);
  if (match) {
    const seconds = Number.parseInt(match[1] ?? "0", 10);
    const fraction = match[2] ?? "";
    const microseconds = Number.parseInt(`${fraction.padEnd(6, "0")}`, 10) || 0;
    return { seconds, microseconds };
  }

  return { seconds: fallbackIndex, microseconds: 0 };
};

const createPcapExport = (
  packets: PacketRecord[],
  filenamePrefix: string,
): PacketExportResult => {
  const headerLength = 24;
  const recordHeaderLength = 16;
  const totalLength = packets.reduce(
    (sum, packet) => sum + recordHeaderLength + packet.payload.length,
    headerLength,
  );

  const buffer = new ArrayBuffer(totalLength);
  const view = new DataView(buffer);
  let offset = 0;

  view.setUint32(offset, 0xa1b2c3d4, true);
  offset += 4;
  view.setUint16(offset, 2, true);
  offset += 2;
  view.setUint16(offset, 4, true);
  offset += 2;
  view.setInt32(offset, 0, true);
  offset += 4;
  view.setUint32(offset, 0, true);
  offset += 4;
  view.setUint32(offset, SNAP_LENGTH, true);
  offset += 4;
  view.setUint32(offset, LINKTYPE_ETHERNET, true);
  offset += 4;

  const bufferView = new Uint8Array(buffer);

  packets.forEach((packet, index) => {
    const { seconds, microseconds } = parseTimestamp(packet.time, index);
    const payload = packet.payload;
    const capturedLength = payload.length;
    const reportedLength = Number.isFinite(packet.length)
      ? Math.max(packet.length, capturedLength)
      : capturedLength;

    view.setUint32(offset, seconds, true);
    offset += 4;
    view.setUint32(offset, microseconds, true);
    offset += 4;
    view.setUint32(offset, capturedLength, true);
    offset += 4;
    view.setUint32(offset, reportedLength, true);
    offset += 4;

    bufferView.set(payload, offset);
    offset += capturedLength;
  });

  const timestamp = new Date().toISOString().replace(/[:]/g, "-");
  const filename = `${filenamePrefix}-${timestamp}.pcap`;

  return {
    blob: new Blob([buffer], { type: PCAP_MIME_TYPE }),
    filename,
    format: "pcap",
  };
};

export const createPacketExport = (
  packets: PacketRecord[],
  options: PacketExportOptions = {},
): PacketExportResult => {
  const { format = "json", filenamePrefix = DEFAULT_PREFIX } = options;

  if (!Array.isArray(packets) || packets.length === 0) {
    throw new Error("No packets available to export.");
  }

  switch (format) {
    case "json":
      return createJsonExport(packets, filenamePrefix);
    case "pcap":
      return createPcapExport(packets, filenamePrefix);
    default:
      throw new Error(`Unsupported export format: ${String(format)}`);
  }
};

export const downloadPacketExport = (
  packets: PacketRecord[],
  options: PacketExportOptions = {},
): PacketExportResult => {
  if (typeof document === "undefined" || typeof URL === "undefined") {
    throw new Error("Packet exports require a browser environment.");
  }

  const result = createPacketExport(packets, options);

  if (!document.body) {
    throw new Error("Unable to access the current document body for download.");
  }

  const urlApi = URL as typeof URL & {
    createObjectURL?: (obj: Blob) => string;
    revokeObjectURL?: (url: string) => void;
  };

  if (
    typeof urlApi.createObjectURL !== "function" ||
    typeof urlApi.revokeObjectURL !== "function"
  ) {
    throw new Error("The current browser does not support Blob downloads.");
  }

  const url = urlApi.createObjectURL(result.blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = result.filename;
  anchor.rel = "noopener";
  anchor.style.position = "absolute";
  anchor.style.left = "-9999px";

  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  setTimeout(() => {
    urlApi.revokeObjectURL(url);
  }, 0);

  return result;
};
