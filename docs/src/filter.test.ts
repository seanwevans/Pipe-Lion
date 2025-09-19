import { describe, expect, it } from "vitest";
import { evaluateFilter, parseFilter, tokenizeFilter } from "./filter";

describe("filter helpers", () => {
  it("parses and evaluates explicit AND expressions", () => {
    const ast = parseFilter(tokenizeFilter("foo && bar"));
    expect(evaluateFilter(ast, "foo and bar".toLowerCase())).toBe(true);
    expect(evaluateFilter(ast, "foo only".toLowerCase())).toBe(false);
    expect(evaluateFilter(ast, "bar only".toLowerCase())).toBe(false);
  });

  it("treats whitespace separated terms as implicit AND", () => {
    const implicit = parseFilter(tokenizeFilter("foo bar"));
    const explicit = parseFilter(tokenizeFilter("foo && bar"));
    expect(implicit).toEqual(explicit);
  });

  it("gives NOT higher precedence than AND", () => {
    const ast = parseFilter(tokenizeFilter("!foo bar"));
    expect(evaluateFilter(ast, "bar only".toLowerCase())).toBe(true);
    expect(evaluateFilter(ast, "foo bar".toLowerCase())).toBe(false);
  });

  it("supports quoted phrases", () => {
    const ast = parseFilter(tokenizeFilter('"foo bar" baz'));
    expect(evaluateFilter(ast, "foo bar baz".toLowerCase())).toBe(true);
    expect(evaluateFilter(ast, "foo qux baz".toLowerCase())).toBe(false);
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
});
