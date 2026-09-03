//! Display-filter compilation and evaluation.
//!
//! The grammar mirrors the one the input box highlights: `&&`/`||`/`!` (or
//! `and`/`or`/`not`), parentheses, quoted strings, `field == value` and
//! `field contains value`, with adjacent terms joined by an implicit AND.
//! Bare words match anywhere in the row.
//!
//! Evaluation lives here rather than in TypeScript because filtering is the
//! expensive operation on a large capture: it touches every packet, and the
//! packets are already in linear memory.

use crate::models::Packet;

#[derive(Debug, PartialEq, Eq)]
pub struct FilterError {
    pub message: String,
    pub start: usize,
    pub end: usize,
}

impl FilterError {
    fn new(message: impl Into<String>, start: usize, end: usize) -> FilterError {
        FilterError {
            message: message.into(),
            start,
            end,
        }
    }
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

/// A row field a comparison can address. Unknown names parse fine but never
/// match, which is what makes `dns.qry.name == x` fail closed rather than loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Time,
    Source,
    Destination,
    Protocol,
    Length,
    Info,
    Unknown,
}

impl Field {
    fn resolve(name: &str) -> Field {
        match name {
            "time" | "timestamp" => Field::Time,
            "src" | "source" => Field::Source,
            "dst" | "destination" => Field::Destination,
            "protocol" | "proto" => Field::Protocol,
            "length" | "len" | "size" => Field::Length,
            "info" | "summary" => Field::Info,
            _ => Field::Unknown,
        }
    }

    fn value(self, packet: &Packet) -> Option<String> {
        match self {
            Field::Time => Some(packet.time.clone()),
            Field::Source => Some(packet.source.clone()),
            Field::Destination => Some(packet.destination.clone()),
            Field::Protocol => Some(packet.protocol.clone()),
            Field::Length => Some(packet.length.to_string()),
            Field::Info => Some(packet.info.clone()),
            Field::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Equals,
    Contains,
}

#[derive(Debug)]
enum Node {
    /// Free text, already lowercased.
    Text(String),
    Comparison {
        field: Field,
        operator: Operator,
        /// Already lowercased.
        value: String,
    },
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Not(Box<Node>),
}

/// A parsed filter, ready to run against any number of packets.
#[derive(Debug)]
pub struct Filter {
    root: Option<Node>,
}

impl Filter {
    /// Compiles an expression. An empty (or whitespace-only) expression matches
    /// every packet, which is what an empty filter box should mean.
    pub fn compile(expression: &str) -> Result<Filter, FilterError> {
        let tokens = tokenize(expression)?;
        if tokens.is_empty() {
            return Ok(Filter { root: None });
        }
        let mut parser = Parser {
            tokens: &tokens,
            index: 0,
            input_length: expression.chars().count(),
        };
        let root = parser.parse_expression()?;
        if parser.index < tokens.len() {
            let token = &tokens[parser.index];
            return Err(FilterError::new(
                "Unexpected trailing tokens",
                token.start,
                token.end,
            ));
        }
        Ok(Filter { root: Some(root) })
    }

    pub fn matches(&self, packet: &Packet) -> bool {
        match &self.root {
            None => true,
            Some(node) => evaluate(node, packet),
        }
    }

    /// Indices of every packet the filter accepts, in capture order.
    pub fn select(&self, packets: &[Packet]) -> Vec<u32> {
        if self.root.is_none() {
            return (0..packets.len() as u32).collect();
        }
        packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| self.matches(packet))
            .map(|(index, _)| index as u32)
            .collect()
    }
}

/// Everything a bare word is matched against: the row as the table renders it.
fn searchable_text(packet: &Packet) -> String {
    format!(
        "{} {} {} {} {} {}",
        packet.time, packet.source, packet.destination, packet.protocol, packet.length, packet.info
    )
    .to_lowercase()
}

fn evaluate(node: &Node, packet: &Packet) -> bool {
    match node {
        Node::Text(needle) => searchable_text(packet).contains(needle.as_str()),
        Node::Comparison {
            field,
            operator,
            value,
        } => match field.value(packet) {
            None => false,
            Some(actual) => {
                let actual = actual.to_lowercase();
                match operator {
                    Operator::Equals => actual == *value,
                    Operator::Contains => actual.contains(value.as_str()),
                }
            }
        },
        Node::And(left, right) => evaluate(left, packet) && evaluate(right, packet),
        Node::Or(left, right) => evaluate(left, packet) || evaluate(right, packet),
        Node::Not(operand) => !evaluate(operand, packet),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Equals,
    Contains,
    Text(String),
}

#[derive(Debug)]
struct Token {
    kind: Kind,
    /// Character offsets, so error ranges line up with what the input box
    /// highlights rather than with UTF-8 byte positions.
    start: usize,
    end: usize,
}

fn is_delimiter(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '(' | ')' | '&' | '|' | '!' | '=')
}

fn tokenize(expression: &str) -> Result<Vec<Token>, FilterError> {
    let chars: Vec<char> = expression.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0usize;

    while index < chars.len() {
        let ch = chars[index];

        if ch.is_whitespace() {
            index += 1;
            continue;
        }

        let simple = match ch {
            '(' => Some(Kind::LParen),
            ')' => Some(Kind::RParen),
            '!' => Some(Kind::Not),
            _ => None,
        };
        if let Some(kind) = simple {
            tokens.push(Token {
                kind,
                start: index,
                end: index + 1,
            });
            index += 1;
            continue;
        }

        if let Some(kind) = double_char_operator(ch) {
            if chars.get(index + 1) == Some(&ch) {
                tokens.push(Token {
                    kind,
                    start: index,
                    end: index + 2,
                });
                index += 2;
                continue;
            }
            return Err(FilterError::new(
                format!("Unexpected '{ch}'"),
                index,
                index + 1,
            ));
        }

        if ch == '"' || ch == '\'' {
            let start = index;
            index += 1;
            let mut value = String::new();
            let mut closed = false;
            while index < chars.len() {
                let current = chars[index];
                if current == '\\' {
                    index += 1;
                    if let Some(escaped) = chars.get(index) {
                        value.push(*escaped);
                        index += 1;
                    }
                    continue;
                }
                if current == ch {
                    closed = true;
                    index += 1;
                    break;
                }
                value.push(current);
                index += 1;
            }
            if !closed {
                return Err(FilterError::new(
                    "Unterminated quoted string",
                    start,
                    chars.len(),
                ));
            }
            tokens.push(Token {
                kind: Kind::Text(value),
                start,
                end: index,
            });
            continue;
        }

        let start = index;
        while index < chars.len() && !is_delimiter(chars[index]) {
            index += 1;
        }
        let raw: String = chars[start..index].iter().collect();
        let kind = match raw.to_lowercase().as_str() {
            "and" => Kind::And,
            "or" => Kind::Or,
            "not" => Kind::Not,
            "contains" => Kind::Contains,
            _ => Kind::Text(raw),
        };
        tokens.push(Token {
            kind,
            start,
            end: index,
        });
    }

    Ok(tokens)
}

fn double_char_operator(ch: char) -> Option<Kind> {
    match ch {
        '&' => Some(Kind::And),
        '|' => Some(Kind::Or),
        '=' => Some(Kind::Equals),
        _ => None,
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    index: usize,
    input_length: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Kind> {
        self.tokens.get(self.index).map(|token| &token.kind)
    }

    fn range_at(&self, index: usize) -> (usize, usize) {
        match self.tokens.get(index) {
            Some(token) => (token.start, token.end),
            None => (self.input_length, self.input_length),
        }
    }

    fn parse_expression(&mut self) -> Result<Node, FilterError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Node, FilterError> {
        let mut node = self.parse_and()?;
        while matches!(self.peek(), Some(Kind::Or)) {
            self.index += 1;
            let right = self.parse_and()?;
            node = Node::Or(Box::new(node), Box::new(right));
        }
        Ok(node)
    }

    fn parse_and(&mut self) -> Result<Node, FilterError> {
        let mut node = self.parse_not()?;
        loop {
            match self.peek() {
                Some(Kind::And) => {
                    self.index += 1;
                    let right = self.parse_not()?;
                    node = Node::And(Box::new(node), Box::new(right));
                }
                // Adjacent terms are an implicit AND.
                Some(Kind::Text(_)) | Some(Kind::LParen) | Some(Kind::Not) => {
                    let right = self.parse_not()?;
                    node = Node::And(Box::new(node), Box::new(right));
                }
                Some(Kind::Or) | Some(Kind::RParen) | None => break,
                Some(_) => {
                    let (start, end) = self.range_at(self.index);
                    return Err(FilterError::new("Unexpected token", start, end));
                }
            }
        }
        Ok(node)
    }

    fn parse_not(&mut self) -> Result<Node, FilterError> {
        if matches!(self.peek(), Some(Kind::Not)) {
            self.index += 1;
            let operand = self.parse_not()?;
            return Ok(Node::Not(Box::new(operand)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Node, FilterError> {
        let Some(token) = self.tokens.get(self.index) else {
            return Err(FilterError::new(
                "Unexpected end of expression",
                self.input_length,
                self.input_length,
            ));
        };

        match &token.kind {
            Kind::Text(text) => {
                let operator = match self.tokens.get(self.index + 1).map(|next| &next.kind) {
                    Some(Kind::Equals) => Some(Operator::Equals),
                    Some(Kind::Contains) => Some(Operator::Contains),
                    _ => None,
                };

                let Some(operator) = operator else {
                    self.index += 1;
                    return Ok(Node::Text(text.to_lowercase()));
                };

                let Some(Kind::Text(value)) =
                    self.tokens.get(self.index + 2).map(|token| &token.kind)
                else {
                    let (start, end) = self.range_at(self.index + 1);
                    return Err(FilterError::new("Expected comparison value", start, end));
                };

                let node = Node::Comparison {
                    field: Field::resolve(&text.to_lowercase()),
                    operator,
                    value: value.to_lowercase(),
                };
                self.index += 3;
                Ok(node)
            }
            Kind::LParen => {
                self.index += 1;
                let node = self.parse_expression()?;
                if !matches!(self.peek(), Some(Kind::RParen)) {
                    let (start, end) = self.range_at(self.index);
                    return Err(FilterError::new("Unmatched '('", start, end));
                }
                self.index += 1;
                Ok(node)
            }
            _ => {
                let (start, end) = self.range_at(self.index);
                Err(FilterError::new("Expected filter term", start, end))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Packet;

    fn packet(protocol: &str, source: &str, destination: &str, info: &str) -> Packet {
        Packet {
            layers: None,
            time: "1.234567".to_string(),
            source: source.to_string(),
            destination: destination.to_string(),
            protocol: protocol.to_string(),
            length: 60,
            info: info.to_string(),
            hex_preview: String::new(),
            ascii_preview: String::new(),
            payload: Vec::new(),
        }
    }

    fn matches(expression: &str, packet: &Packet) -> bool {
        Filter::compile(expression)
            .expect("expression compiles")
            .matches(packet)
    }

    fn error(expression: &str) -> FilterError {
        Filter::compile(expression).expect_err("expression is rejected")
    }

    fn sample() -> Packet {
        packet(
            "TCP",
            "10.0.0.42:51234",
            "8.8.8.8:443",
            "TLSv1.3 Client Hello",
        )
    }

    #[test]
    fn an_empty_expression_matches_everything() {
        assert!(matches("", &sample()));
        assert!(matches("   ", &sample()));
    }

    #[test]
    fn bare_words_match_any_column() {
        let packet = sample();

        assert!(matches("tcp", &packet));
        assert!(matches("8.8.8.8", &packet));
        assert!(matches("\"client hello\"", &packet));
        assert!(matches("1.234567", &packet));
        assert!(matches("60", &packet));
        assert!(!matches("quic", &packet));
    }

    #[test]
    fn bare_words_are_case_insensitive() {
        assert!(matches("TCP", &sample()));
        assert!(matches("tCp", &sample()));
    }

    #[test]
    fn equality_compares_whole_field_values() {
        let packet = sample();

        assert!(matches("protocol == tcp", &packet));
        assert!(matches("protocol == \"TCP\"", &packet));
        assert!(!matches("protocol == tc", &packet));
        assert!(matches("length == 60", &packet));
    }

    #[test]
    fn contains_matches_substrings() {
        let packet = sample();

        assert!(matches("src contains 10.0.0", &packet));
        assert!(matches("dst contains 8.8", &packet));
        assert!(matches("info contains hello", &packet));
        assert!(!matches("src contains 192.168", &packet));
    }

    #[test]
    fn field_aliases_resolve_to_the_same_column() {
        let packet = sample();

        for alias in ["src", "source"] {
            assert!(matches(&format!("{alias} contains 10.0.0.42"), &packet));
        }
        for alias in ["dst", "destination"] {
            assert!(matches(&format!("{alias} contains 8.8.8.8"), &packet));
        }
        for alias in ["protocol", "proto"] {
            assert!(matches(&format!("{alias} == tcp"), &packet));
        }
        for alias in ["length", "len", "size"] {
            assert!(matches(&format!("{alias} == 60"), &packet));
        }
        for alias in ["info", "summary"] {
            assert!(matches(&format!("{alias} contains hello"), &packet));
        }
        for alias in ["time", "timestamp"] {
            assert!(matches(&format!("{alias} == 1.234567"), &packet));
        }
    }

    #[test]
    fn an_unknown_field_never_matches() {
        assert!(!matches("nonsense == tcp", &sample()));
        assert!(!matches("nonsense contains t", &sample()));
        // ...and negating it still matches, rather than erroring out.
        assert!(matches("!(nonsense == tcp)", &sample()));
    }

    #[test]
    fn boolean_operators_combine_terms() {
        let packet = sample();

        assert!(matches("protocol == tcp && dst contains 8.8", &packet));
        assert!(matches("protocol == udp || dst contains 8.8", &packet));
        assert!(!matches("protocol == udp && dst contains 8.8", &packet));
        assert!(matches("protocol == tcp and dst contains 8.8", &packet));
        assert!(matches("protocol == udp or protocol == tcp", &packet));
    }

    #[test]
    fn negation_applies_to_the_next_term_only() {
        let packet = sample();

        assert!(matches("!(protocol == udp)", &packet));
        assert!(matches("not protocol == udp", &packet));
        assert!(!matches("!protocol == tcp", &packet));
        assert!(matches("!!protocol == tcp", &packet));
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // udp && quic is false, so the result is decided by the leading term.
        assert!(matches("tcp || protocol == udp && quic", &sample()));
    }

    #[test]
    fn adjacent_terms_are_an_implicit_and() {
        let packet = sample();

        assert!(matches("tcp 8.8.8.8", &packet));
        assert!(!matches("tcp quic", &packet));
    }

    #[test]
    fn parentheses_override_precedence() {
        let packet = sample();

        assert!(!matches("(tcp || udp) && quic", &packet));
        assert!(matches("(quic || tcp) && 8.8.8.8", &packet));
    }

    #[test]
    fn quoted_strings_keep_spaces_and_escapes() {
        let packet = sample();

        assert!(matches("info contains \"client hello\"", &packet));
        assert!(matches("'client hello'", &packet));
        assert!(matches(
            "info contains \"client \\\"hello\" || tcp",
            &packet
        ));
    }

    #[test]
    fn select_returns_matching_indices_in_capture_order() {
        let packets = vec![
            packet("TCP", "a", "b", "one"),
            packet("UDP", "c", "d", "two"),
            packet("TCP", "e", "f", "three"),
        ];

        let filter = Filter::compile("protocol == tcp").expect("compiles");

        assert_eq!(filter.select(&packets), vec![0, 2]);
        assert_eq!(Filter::compile("").unwrap().select(&packets), vec![0, 1, 2]);
        assert!(
            Filter::compile("protocol == sctp")
                .unwrap()
                .select(&packets)
                .is_empty()
        );
    }

    #[test]
    fn reports_syntax_errors_with_character_ranges() {
        assert_eq!(error("tcp &"), FilterError::new("Unexpected '&'", 4, 5));
        assert_eq!(error("tcp |").message, "Unexpected '|'");
        assert_eq!(error("tcp =").message, "Unexpected '='");
        assert_eq!(
            error("\"unclosed"),
            FilterError::new("Unterminated quoted string", 0, 9)
        );
        assert_eq!(error("(tcp").message, "Unmatched '('");
        assert_eq!(error("protocol ==").message, "Expected comparison value");
        assert_eq!(error("tcp &&").message, "Unexpected end of expression");
        assert_eq!(error(")").message, "Expected filter term");
        assert_eq!(error("tcp )").message, "Unexpected trailing tokens");
    }

    #[test]
    fn error_ranges_are_character_offsets_not_byte_offsets() {
        // The em dash ahead of the bad token is three bytes but one character.
        let err = error("info contains \u{2014} &");

        assert_eq!(err.start, 16);
        assert_eq!(err.end, 17);
    }
}
