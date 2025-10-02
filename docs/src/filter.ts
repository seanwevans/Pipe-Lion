export type PacketRecord = {
  time?: string;
  src?: string;
  source?: string;
  dst?: string;
  destination?: string;
  protocol?: string;
  length?: string | number;
  info: string;
  summary?: string;
  payload?: Uint8Array;
  [key: string]: string | number | Uint8Array | undefined;
};

export type FilterNode =
  | { type: "text"; value: string }
  | {
      type: "comparison";
      field: string;
      operator: "eq" | "contains";
      value: string;
    }
  | { type: "and"; left: FilterNode; right: FilterNode }
  | { type: "or"; left: FilterNode; right: FilterNode }
  | { type: "not"; operand: FilterNode };

export type FilterToken =
  | { type: "LPAREN" }
  | { type: "RPAREN" }
  | { type: "AND" }
  | { type: "OR" }
  | { type: "NOT" }
  | { type: "EQ" }
  | { type: "CONTAINS" }
  | { type: "TEXT"; value: string };

export type FilterTokenWithRange = FilterToken & {
  start: number;
  end: number;
  raw: string;
};

export class FilterSyntaxError extends Error {
  start: number;
  end: number;
  tokens?: FilterTokenWithRange[];

  constructor(
    message: string,
    range?: { start: number; end: number },
    tokens?: FilterTokenWithRange[],
  ) {
    super(message);
    this.name = "FilterSyntaxError";
    Object.setPrototypeOf(this, new.target.prototype);
    this.start = range?.start ?? 0;
    this.end = range?.end ?? this.start;
    if (tokens) {
      this.tokens = tokens;
    }
  }
}

function createToken(
  token: FilterToken,
  start: number,
  end: number,
  raw: string,
): FilterTokenWithRange {
  return { ...token, start, end, raw };
}

function tokenizeFilterDetailed(expression: string): FilterTokenWithRange[] {
  const tokens: FilterTokenWithRange[] = [];
  let index = 0;

  while (index < expression.length) {
    const char = expression[index];

    if (/\s/.test(char)) {
      index += 1;
      continue;
    }

    if (char === "(") {
      tokens.push(createToken({ type: "LPAREN" }, index, index + 1, char));
      index += 1;
      continue;
    }

    if (char === ")") {
      tokens.push(createToken({ type: "RPAREN" }, index, index + 1, char));
      index += 1;
      continue;
    }

    if (char === "&") {
      if (expression[index + 1] === "&") {
        tokens.push(
          createToken({ type: "AND" }, index, index + 2, expression.slice(index, index + 2)),
        );
        index += 2;
        continue;
      }
      throw new FilterSyntaxError(
        "Unexpected '&'",
        { start: index, end: index + 1 },
        tokens,
      );
    }

    if (char === "|") {
      if (expression[index + 1] === "|") {
        tokens.push(
          createToken({ type: "OR" }, index, index + 2, expression.slice(index, index + 2)),
        );
        index += 2;
        continue;
      }
      throw new FilterSyntaxError(
        "Unexpected '|'",
        { start: index, end: index + 1 },
        tokens,
      );
    }

    if (char === "!") {
      tokens.push(createToken({ type: "NOT" }, index, index + 1, char));
      index += 1;
      continue;
    }

    if (char === "=") {
      if (expression[index + 1] === "=") {
        tokens.push(
          createToken({ type: "EQ" }, index, index + 2, expression.slice(index, index + 2)),
        );
        index += 2;
        continue;
      }
      throw new FilterSyntaxError(
        "Unexpected '='",
        { start: index, end: index + 1 },
        tokens,
      );
    }

    if (char === '"' || char === "'") {
      const quote = char;
      index += 1;
      let value = "";
      let closed = false;
      const start = index - 1;

      while (index < expression.length) {
        const current = expression[index];
        if (current === "\\") {
          index += 1;
          if (index < expression.length) {
            value += expression[index];
            index += 1;
          }
          continue;
        }

        if (current === quote) {
          closed = true;
          index += 1;
          break;
        }

        value += current;
        index += 1;
      }

      if (!closed) {
        throw new FilterSyntaxError(
          "Unterminated quoted string",
          { start, end: expression.length },
          tokens,
        );
      }

      tokens.push(
        createToken({ type: "TEXT", value }, start, index, expression.slice(start, index)),
      );
      continue;
    }

    const start = index;
    while (
      index < expression.length &&
      !/\s|\(|\)|&|\||!|=/u.test(expression[index])
    ) {
      index += 1;
    }

    const raw = expression.slice(start, index);
    const lowered = raw.toLowerCase();

    if (lowered === "and") {
      tokens.push(createToken({ type: "AND" }, start, index, raw));
      continue;
    }

    if (lowered === "or") {
      tokens.push(createToken({ type: "OR" }, start, index, raw));
      continue;
    }

    if (lowered === "not") {
      tokens.push(createToken({ type: "NOT" }, start, index, raw));
      continue;
    }

    if (lowered === "contains") {
      tokens.push(createToken({ type: "CONTAINS" }, start, index, raw));
      continue;
    }

    if (raw.length === 0) {
      continue;
    }

    tokens.push(createToken({ type: "TEXT", value: raw }, start, index, raw));
  }

  return tokens;
}

export function tokenizeFilter(expression: string): FilterToken[] {
  return tokenizeFilterDetailed(expression).map(({ start, end, raw, ...token }) => token);
}

type ParseOptions = {
  metadata?: FilterTokenWithRange[];
  inputLength?: number;
};

function rangeFor(
  metadata: FilterTokenWithRange[] | undefined,
  tokenIndex: number,
  fallback: number,
): { start: number; end: number } {
  const token = metadata?.[tokenIndex];
  if (token) {
    return { start: token.start, end: token.end };
  }
  return { start: fallback, end: fallback };
}

export function parseFilter(
  tokens: FilterToken[],
  options: ParseOptions = {},
): FilterNode {
  let index = 0;
  const metadata = options.metadata;
  const inputLength =
    options.inputLength ?? metadata?.[metadata.length - 1]?.end ?? 0;

  function parseExpression(): FilterNode {
    return parseOr();
  }

  function parseOr(): FilterNode {
    let node = parseAnd();

    while (index < tokens.length && tokens[index].type === "OR") {
      index += 1;
      const right = parseAnd();
      node = { type: "or", left: node, right };
    }

    return node;
  }

  function parseAnd(): FilterNode {
    let node = parseNot();

    while (index < tokens.length) {
      const next = tokens[index];
      if (next.type === "AND") {
        index += 1;
        const right = parseNot();
        node = { type: "and", left: node, right };
        continue;
      }

      if (next.type === "OR" || next.type === "RPAREN") {
        break;
      }

      if (
        next.type === "TEXT" ||
        next.type === "LPAREN" ||
        next.type === "NOT"
      ) {
        const right = parseNot();
        node = { type: "and", left: node, right };
        continue;
      }

      throw new FilterSyntaxError(
        "Unexpected token",
        rangeFor(metadata, index, inputLength),
      );
    }

    return node;
  }

  function parseNot(): FilterNode {
    if (index < tokens.length && tokens[index].type === "NOT") {
      index += 1;
      const operand = parseNot();
      return { type: "not", operand };
    }

    return parsePrimary();
  }

  function parsePrimary(): FilterNode {
    const token = tokens[index];
    if (!token) {
      throw new FilterSyntaxError(
        "Unexpected end of expression",
        { start: inputLength, end: inputLength },
      );
    }

    if (token.type === "TEXT") {
      const next = tokens[index + 1];
      if (next && (next.type === "EQ" || next.type === "CONTAINS")) {
        const valueToken = tokens[index + 2];
        if (!valueToken || valueToken.type !== "TEXT") {
          throw new FilterSyntaxError(
            "Expected comparison value",
            rangeFor(metadata, index + 1, inputLength),
          );
        }

        const operator = next.type === "EQ" ? "eq" : "contains";
        const field = token.value.toLowerCase();
        const value = valueToken.value;
        index += 3;
        return { type: "comparison", field, operator, value };
      }

      index += 1;
      return { type: "text", value: token.value.toLowerCase() };
    }

    if (token.type === "LPAREN") {
      index += 1;
      const node = parseExpression();
      if (tokens[index]?.type !== "RPAREN") {
        throw new FilterSyntaxError(
          "Unmatched '('",
          rangeFor(metadata, index, inputLength),
        );
      }
      index += 1;
      return node;
    }

    throw new FilterSyntaxError(
      "Expected filter term",
      rangeFor(metadata, index, inputLength),
    );
  }

  const node = parseExpression();

  if (index < tokens.length) {
    throw new FilterSyntaxError(
      "Unexpected trailing tokens",
      rangeFor(metadata, index, inputLength),
    );
  }

  return node;
}

export type FilterAnalysis = {
  tokens: FilterTokenWithRange[];
  ast: FilterNode | null;
  error: FilterSyntaxError | null;
};

export function analyzeFilter(expression: string): FilterAnalysis {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    return { tokens: [], ast: null, error: null };
  }

  let detailedTokens: FilterTokenWithRange[] = [];

  try {
    detailedTokens = tokenizeFilterDetailed(expression);
  } catch (err) {
    if (err instanceof FilterSyntaxError) {
      return {
        tokens: err.tokens ?? detailedTokens,
        ast: null,
        error: err,
      };
    }

    return {
      tokens: [],
      ast: null,
      error: new FilterSyntaxError(
        err instanceof Error ? err.message : "Invalid display filter",
        { start: expression.length, end: expression.length },
      ),
    };
  }

  if (detailedTokens.length === 0) {
    return { tokens: detailedTokens, ast: null, error: null };
  }

  try {
    const ast = parseFilter(
      detailedTokens.map(({ start, end, raw, ...token }) => token),
      { metadata: detailedTokens, inputLength: expression.length },
    );
    return { tokens: detailedTokens, ast, error: null };
  } catch (err) {
    if (err instanceof FilterSyntaxError) {
      if (!err.tokens) {
        err.tokens = detailedTokens;
      }
      return { tokens: detailedTokens, ast: null, error: err };
    }

    return {
      tokens: detailedTokens,
      ast: null,
      error: new FilterSyntaxError(
        err instanceof Error ? err.message : "Invalid display filter",
        { start: expression.length, end: expression.length },
        detailedTokens,
      ),
    };
  }
}

export const FIELD_ALIASES: Record<string, string[]> = {
  src: ["src", "source"],
  source: ["src", "source"],
  dst: ["dst", "destination"],
  destination: ["dst", "destination"],
  protocol: ["protocol"],
  proto: ["protocol"],
  time: ["time", "timestamp"],
  timestamp: ["time", "timestamp"],
  length: ["length", "len", "size"],
  len: ["length", "len", "size"],
  size: ["length", "len", "size"],
  info: ["info", "summary"],
  summary: ["summary", "info"],
};

function resolveFieldValue(
  packet: PacketRecord,
  field: string,
): string | number | undefined {
  const candidates = FIELD_ALIASES[field] ?? [field];
  for (const candidate of candidates) {
    const value = packet[candidate];
    if (value === undefined) {
      continue;
    }
    if (typeof value === "string" || typeof value === "number") {
      return value;
    }
  }
  return undefined;
}

export function evaluateFilter(
  node: FilterNode,
  packet: PacketRecord,
  searchableText?: string,
): boolean {
  switch (node.type) {
    case "text": {
      const infoMatch = packet.info.toLowerCase().includes(node.value);
      if (infoMatch) {
        return true;
      }

      if (typeof packet.summary === "string") {
        return packet.summary.toLowerCase().includes(node.value);
      }

      if (typeof searchableText === "string") {
        return searchableText.includes(node.value);
      }

      return false;
    }

    case "comparison": {
      const value = resolveFieldValue(packet, node.field);
      if (value === undefined) {
        return false;
      }
      const haystack = String(value).toLowerCase();
      const needle = node.value.toLowerCase();
      if (node.operator === "eq") {
        return haystack === needle;
      }
      if (node.operator === "contains") {
        return haystack.includes(needle);
      }
      return false;
    }
    case "and":
      return (
        evaluateFilter(node.left, packet, searchableText) &&
        evaluateFilter(node.right, packet, searchableText)
      );
    case "or":
      return (
        evaluateFilter(node.left, packet, searchableText) ||
        evaluateFilter(node.right, packet, searchableText)
      );
    case "not":
      return !evaluateFilter(node.operand, packet, searchableText);
    default:
      return true;
  }
}
