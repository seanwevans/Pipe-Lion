import { describe, expect, it } from "vitest";
import {
  evaluateFilter,
  parseFilter,
  tokenizeFilter,
  type PacketRecord,
} from "./filter";

const makePacket = (overrides: Partial<PacketRecord>): PacketRecord => {
  const { info, ...rest } = overrides;
  const base: PacketRecord = {
    info: typeof info === "string" ? info : "",
  };
  return Object.assign(base, rest);
};

describe("filter helpers", () => {
  it("parses and evaluates explicit AND expressions", () => {
    const ast = parseFilter(tokenizeFilter("foo && bar"));
    expect(evaluateFilter(ast, makePacket({ info: "foo and bar" }))).toBe(true);
    expect(evaluateFilter(ast, makePacket({ info: "foo only" }))).toBe(false);
    expect(evaluateFilter(ast, makePacket({ info: "bar only" }))).toBe(false);
  });

  it("treats whitespace separated terms as implicit AND", () => {
    const implicit = parseFilter(tokenizeFilter("foo bar"));
    const explicit = parseFilter(tokenizeFilter("foo && bar"));
    expect(implicit).toEqual(explicit);
  });

  it("gives NOT higher precedence than AND", () => {
    const ast = parseFilter(tokenizeFilter("!foo bar"));
    expect(evaluateFilter(ast, makePacket({ info: "bar only" }))).toBe(true);
    expect(evaluateFilter(ast, makePacket({ info: "foo bar" }))).toBe(false);
  });

  it("supports quoted phrases", () => {
    const ast = parseFilter(tokenizeFilter('"foo bar" baz'));
    expect(evaluateFilter(ast, makePacket({ info: "foo bar baz" }))).toBe(true);
    expect(evaluateFilter(ast, makePacket({ info: "foo qux baz" }))).toBe(
      false,
    );
  });

  it("throws on common syntax errors", () => {
    expect(() => tokenizeFilter('"unterminated')).toThrowError(
      /Unterminated quoted string/,
    );
    expect(() => parseFilter(tokenizeFilter("foo &&"))).toThrowError(
      /Unexpected end of expression|Expected filter term/,
    );
    expect(() => parseFilter(tokenizeFilter("(foo"))).toThrowError(
      /Unmatched '\('/,
    );
    expect(() => parseFilter(tokenizeFilter("foo ) bar"))).toThrowError(
      /Unexpected trailing tokens|Expected filter term|Unexpected token/,
    );
  });

  it("evaluates equality and substring comparisons against packet fields", () => {
    const packet = makePacket({
      info: "TCP handshake",
      protocol: "TCP",
      src: "10.0.0.42",
      dst: "8.8.8.8",
      length: 60,
    });
    const ast = parseFilter(
      tokenizeFilter('protocol == "tcp" && src contains 10.0.0'),
    );
    expect(evaluateFilter(ast, packet)).toBe(true);

    const mismatch = makePacket({
      info: "UDP packet",
      protocol: "udp",
      src: "10.0.0.42",
    });
    expect(evaluateFilter(ast, mismatch)).toBe(false);
  });

  it("matches field comparisons when searchable text omits the field value", () => {
    const ast = parseFilter(tokenizeFilter('protocol == "tcp"'));
    const packet = makePacket({
      info: "Generic packet",
      protocol: "TCP",
    });

    const searchableText = "generic packet";
    expect(evaluateFilter(ast, packet, searchableText)).toBe(true);

    const mismatch = makePacket({
      info: "Generic packet",
      protocol: "udp",
    });
    expect(evaluateFilter(ast, mismatch, searchableText)).toBe(false);
  });

  it("supports negations and boolean combinations with comparisons", () => {
    const ast = parseFilter(
      tokenizeFilter(
        '!(protocol == "udp") && (dst contains 8.8 || info contains handshake)',
      ),
    );
    const packet = makePacket({
      info: "TLS handshake to 8.8.8.8",
      protocol: "TCP",
      dst: "8.8.8.8",
    });
    expect(evaluateFilter(ast, packet)).toBe(true);

    const nonMatching = makePacket({
      info: "UDP request",
      protocol: "udp",
      dst: "1.1.1.1",
    });
    expect(evaluateFilter(ast, nonMatching)).toBe(false);
  });

  it("falls back to searching the Info column when a field is missing", () => {
    const ast = parseFilter(tokenizeFilter("dst contains example || request"));
    const packet = makePacket({ info: "HTTP request to example.com" });
    expect(evaluateFilter(ast, packet)).toBe(true);

    const mismatch = makePacket({ info: "DNS query" });
    expect(evaluateFilter(ast, mismatch)).toBe(false);
  });
});
