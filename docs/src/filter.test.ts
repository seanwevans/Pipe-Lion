import { describe, expect, it } from "vitest";
import {
  analyzeFilter,
  parseFilter,
  tokenizeFilter,
  type FilterNode,
} from "./filter";

// Evaluation lives in the Rust core (`core/src/filter.rs`); what TypeScript
// still owns is turning text into an AST and locating syntax errors for the
// input box, so that is what these cover.

const ast = (expression: string): FilterNode =>
  parseFilter(tokenizeFilter(expression));

describe("tokenizeFilter", () => {
  it("recognizes symbolic and keyword operators alike", () => {
    expect(tokenizeFilter("a && b")).toEqual(tokenizeFilter("a and b"));
    expect(tokenizeFilter("a || b")).toEqual(tokenizeFilter("a or b"));
    expect(tokenizeFilter("!a")).toEqual(tokenizeFilter("not a"));
  });

  it("keeps quoted phrases intact and honours escapes", () => {
    expect(tokenizeFilter('"foo bar"')).toEqual([
      { type: "TEXT", value: "foo bar" },
    ]);
    expect(tokenizeFilter('"foo \\"bar"')).toEqual([
      { type: "TEXT", value: 'foo "bar' },
    ]);
    expect(tokenizeFilter("'single quoted'")).toEqual([
      { type: "TEXT", value: "single quoted" },
    ]);
  });
});

describe("parseFilter", () => {
  it("treats whitespace separated terms as implicit AND", () => {
    expect(ast("foo bar")).toEqual(ast("foo && bar"));
  });

  it("gives NOT higher precedence than AND", () => {
    expect(ast("!foo bar")).toEqual({
      type: "and",
      left: { type: "not", operand: { type: "text", value: "foo" } },
      right: { type: "text", value: "bar" },
    });
  });

  it("gives AND higher precedence than OR", () => {
    expect(ast("a || b && c")).toEqual({
      type: "or",
      left: { type: "text", value: "a" },
      right: {
        type: "and",
        left: { type: "text", value: "b" },
        right: { type: "text", value: "c" },
      },
    });
  });

  it("lets parentheses override precedence", () => {
    expect(ast("(a || b) && c")).toEqual({
      type: "and",
      left: {
        type: "or",
        left: { type: "text", value: "a" },
        right: { type: "text", value: "b" },
      },
      right: { type: "text", value: "c" },
    });
  });

  it("lowercases field names and free text but not comparison values", () => {
    expect(ast("Protocol == TCP")).toEqual({
      type: "comparison",
      field: "protocol",
      operator: "eq",
      value: "TCP",
    });
    expect(ast("TCP")).toEqual({ type: "text", value: "tcp" });
  });

  it("parses contains comparisons", () => {
    expect(ast("src contains 10.0.0")).toEqual({
      type: "comparison",
      field: "src",
      operator: "contains",
      value: "10.0.0",
    });
  });

  it("throws on common syntax errors", () => {
    expect(() => tokenizeFilter('"unterminated')).toThrowError(
      /Unterminated quoted string/,
    );
    expect(() => tokenizeFilter("foo &")).toThrowError(/Unexpected '&'/);
    expect(() => parseFilter(tokenizeFilter("foo &&"))).toThrowError(
      /Unexpected end of expression|Expected filter term/,
    );
    expect(() => parseFilter(tokenizeFilter("(foo"))).toThrowError(
      /Unmatched '\('/,
    );
    expect(() => parseFilter(tokenizeFilter("foo ) bar"))).toThrowError(
      /Unexpected trailing tokens|Expected filter term|Unexpected token/,
    );
    expect(() => parseFilter(tokenizeFilter("protocol =="))).toThrowError(
      /Expected comparison value/,
    );
  });
});

describe("analyzeFilter", () => {
  it("returns an empty analysis for a blank expression", () => {
    expect(analyzeFilter("   ")).toEqual({
      tokens: [],
      ast: null,
      error: null,
    });
  });

  it("reports the character range of a syntax error", () => {
    const { ast: parsed, error } = analyzeFilter("protocol == ");

    expect(parsed).toBeNull();
    expect(error?.message).toMatch(/Expected comparison value/);
    expect(error?.start).toBe(9);
    expect(error?.end).toBe(11);
  });

  it("carries the tokens alongside a failed parse so highlighting still works", () => {
    const { tokens, error } = analyzeFilter("(foo");

    expect(error).not.toBeNull();
    expect(tokens.map((token) => token.type)).toEqual(["LPAREN", "TEXT"]);
  });
});
