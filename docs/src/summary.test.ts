import { describe, expect, it, vi } from "vitest";
import type { PacketRecord as FilterPacketRecord } from "./filter";
import { parsePacketSummaryLine } from "./summary";

function baseRecord(info: string): FilterPacketRecord {
  return { info, summary: info };
}

describe("parsePacketSummaryLine", () => {
  it("returns plain text summaries without parsing JSON", () => {
    const spy = vi.spyOn(JSON, "parse");
    const text = "Simple packet description";

    const result = parsePacketSummaryLine(text);

    expect(result).toEqual(baseRecord(text));
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("parses structured JSON summaries", () => {
    const payload = JSON.stringify({
      info: "Packet info",
      summary: "Detailed summary",
      time: "10:15:00",
      src: "10.0.0.1",
      dst: "10.0.0.2",
      protocol: "TCP",
      length: 1500,
      extra: "value",
    });

    const result = parsePacketSummaryLine(payload);

    expect(result).toMatchObject({
      info: "Packet info",
      summary: "Detailed summary",
      time: "10:15:00",
      src: "10.0.0.1",
      dst: "10.0.0.2",
      protocol: "TCP",
      length: 1500,
      extra: "value",
    });
  });

  it("ignores JSON parsing for non-object strings", () => {
    const spy = vi.spyOn(JSON, "parse");
    const notJsonObject = "[1, 2, 3]";

    const result = parsePacketSummaryLine(notJsonObject);

    expect(result).toEqual(baseRecord(notJsonObject));
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("skips parsing invalid object-like text", () => {
    const spy = vi.spyOn(JSON, "parse");
    const invalid = '{"info": "Missing brace"';

    const result = parsePacketSummaryLine(invalid);

    expect(result).toEqual(baseRecord(invalid));
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
