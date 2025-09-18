export type FilterNode =
  | { type: "text"; value: string }
  | { type: "and"; left: FilterNode; right: FilterNode }
  | { type: "or"; left: FilterNode; right: FilterNode }
  | { type: "not"; operand: FilterNode };

export type FilterToken =
  | { type: "LPAREN" }
  | { type: "RPAREN" }
  | { type: "AND" }
  | { type: "OR" }
  | { type: "NOT" }
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
      !/\s|\(|\)|&|\||!/u.test(expression[index])
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

      if (next.type === "TEXT" || next.type === "LPAREN" || next.type === "NOT") {
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

export function evaluateFilter(node: FilterNode, line: string): boolean {
  switch (node.type) {
    case "text":
      return line.includes(node.value);
    case "and":
      return evaluateFilter(node.left, line) && evaluateFilter(node.right, line);
    case "or":
      return evaluateFilter(node.left, line) || evaluateFilter(node.right, line);
    case "not":
      return !evaluateFilter(node.operand, line);
    default:
      return true;
  }
}
