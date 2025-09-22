import type { PacketRecord as FilterPacketRecord } from "./filter";

function toOptionalString(value: unknown): string | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

function toOptionalNumericLike(value: unknown): string | number | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "boolean") {
    return value ? "1" : "0";
  }
  return undefined;
}

function looksLikeJsonObject(value: string): boolean {
  return value.startsWith("{") && value.endsWith("}");
}

export function parsePacketSummaryLine(line: string): FilterPacketRecord {
  const trimmed = line.trim();
  const record: FilterPacketRecord = { info: trimmed, summary: trimmed };

  if (trimmed.length === 0) {
    return record;
  }

  if (!looksLikeJsonObject(trimmed)) {
    return record;
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return record;
    }

    const data = parsed as Record<string, unknown>;

    const infoValue =
      toOptionalString(data.info) ??
      toOptionalString(data.Info) ??
      toOptionalString(data.summary) ??
      toOptionalString(data.Summary);
    if (infoValue) {
      record.info = infoValue;
    }

    const summaryValue =
      toOptionalString(data.summary) ?? toOptionalString(data.Summary);
    if (summaryValue) {
      record.summary = summaryValue;
    }

    const timeValue =
      toOptionalString(data.time) ??
      toOptionalString(data.timestamp) ??
      toOptionalString(data.Time) ??
      toOptionalString(data.Timestamp);
    if (timeValue) {
      record.time = timeValue;
    }

    const srcValue =
      toOptionalString(data.src) ??
      toOptionalString(data.source) ??
      toOptionalString(data.Source);
    if (srcValue) {
      record.src = srcValue;
      record.source = srcValue;
    }

    const dstValue =
      toOptionalString(data.dst) ??
      toOptionalString(data.destination) ??
      toOptionalString(data.Dst) ??
      toOptionalString(data.Destination);
    if (dstValue) {
      record.dst = dstValue;
      record.destination = dstValue;
    }

    const protocolValue =
      toOptionalString(data.protocol) ??
      toOptionalString(data.proto) ??
      toOptionalString(data.Protocol) ??
      toOptionalString(data.Proto);
    if (protocolValue) {
      record.protocol = protocolValue;
    }

    const lengthValue =
      toOptionalNumericLike(data.length) ??
      toOptionalNumericLike(data.len) ??
      toOptionalNumericLike(data.size) ??
      toOptionalNumericLike(data.Length) ??
      toOptionalNumericLike(data.Len) ??
      toOptionalNumericLike(data.Size);
    if (lengthValue !== undefined) {
      record.length = lengthValue;
    }

    for (const [key, value] of Object.entries(data)) {
      if (value === null || value === undefined) {
        continue;
      }
      if (key in record) {
        continue;
      }
      if (typeof value === "string" || typeof value === "number") {
        record[key] = value;
        continue;
      }
      if (typeof value === "boolean") {
        record[key] = value ? "true" : "false";
      }
    }

    record.summary ??= record.info;
    return record;
  } catch (error) {
    if (import.meta.env.DEV) {
      console.debug("Failed to parse packet summary line", error);
    }
  }

  return record;
}
