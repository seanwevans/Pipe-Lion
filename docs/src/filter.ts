export type PacketRecord = {
  time?: string;
  src?: string;
  dst?: string;
  protocol?: string;
  length?: string | number;
  info: string;
  summary?: string;
  [key: string]: string | number | undefined;
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

export function tokenizeFilter(expression: string): FilterToken[] {
  const tokens: FilterToken[] = [];
  let index = 0;

  while (index < expression.length) {
    const char = expression[index];

    if (/\s/.test(char)) {
      index += 1;
      continue;
    }

    if (char === "(") {
      tokens.push({ type: "LPAREN" });
      index += 1;
      continue;
    }

    if (char === ")") {
      tokens.push({ type: "RPAREN" });
      index += 1;
      continue;
    }

    if (char === "&") {
      if (expression[index + 1] === "&") {
        tokens.push({ type: "AND" });
        index += 2;
        continue;
      }
      throw new Error("Unexpected '&'");
    }

    if (char === "|") {
      if (expression[index + 1] === "|") {
        tokens.push({ type: "OR" });
        index += 2;
        continue;
      }
      throw new Error("Unexpected '|'");
    }

    if (char === "!") {
      tokens.push({ type: "NOT" });
      index += 1;
      continue;
    }

    if (char === "=") {
      if (expression[index + 1] === "=") {
        tokens.push({ type: "EQ" });
        index += 2;
        continue;
      }
      throw new Error("Unexpected '='");
    }

    if (char === '"' || char === "'") {
      const quote = char;
      index += 1;
      let value = "";
      let closed = false;

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
        throw new Error("Unterminated quoted string");
      }

      tokens.push({ type: "TEXT", value });
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
      tokens.push({ type: "AND" });
      continue;
    }

    if (lowered === "or") {
      tokens.push({ type: "OR" });
      continue;
    }

    if (lowered === "not") {
      tokens.push({ type: "NOT" });
      continue;
    }

    if (lowered === "contains") {
      tokens.push({ type: "CONTAINS" });
      continue;
    }

    if (raw.length === 0) {
      continue;
    }

    tokens.push({ type: "TEXT", value: raw });
  }

  return tokens;
}

export function parseFilter(tokens: FilterToken[]): FilterNode {
  let index = 0;

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

      throw new Error("Unexpected token");
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
      throw new Error("Unexpected end of expression");
    }

    if (token.type === "TEXT") {
      const next = tokens[index + 1];
      if (next && (next.type === "EQ" || next.type === "CONTAINS")) {
        const valueToken = tokens[index + 2];
        if (!valueToken || valueToken.type !== "TEXT") {
          throw new Error("Expected comparison value");
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
        throw new Error("Unmatched '('");
      }
      index += 1;
      return node;
    }

    throw new Error("Expected filter term");
  }

  const node = parseExpression();

  if (index < tokens.length) {
    throw new Error("Unexpected trailing tokens");
  }

  return node;
}

const FIELD_ALIASES: Record<string, string[]> = {
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
    if (value !== undefined) {
      return value;
    }
  }
  return undefined;
}

export function evaluateFilter(
  node: FilterNode,
  packet: PacketRecord,
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
        evaluateFilter(node.left, packet) && evaluateFilter(node.right, packet)
      );
    case "or":
      return (
        evaluateFilter(node.left, packet) || evaluateFilter(node.right, packet)
      );
    case "not":
      return !evaluateFilter(node.operand, packet);
    default:
      return true;
  }
}
