import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  analyzeFilter,
  FIELD_ALIASES,
  FilterSyntaxError,
  type FilterAnalysis,
  type FilterNode,
  type FilterTokenWithRange,
} from "./filter";
import { createStoredList } from "./storage";

type FilterChangeDetails = {
  text: string;
  ast: FilterNode | null;
  error: FilterSyntaxError | null;
  errorMessage: string | null;
};

type FilterInputProps = {
  id: string;
  label: string;
  placeholder?: string;
  describedById?: string;
  value?: string;
  onFilterChange(details: FilterChangeDetails): void;
};

type SuggestionContext = "field" | "operator" | "value" | "logical";

type SuggestionItem = {
  value: string;
  label: string;
  description?: string;
  kind: SuggestionContext | "not";
};

type ActiveSegment = { start: number; text: string };

const FIELD_ALIAS_MAP = (() => {
  const map = new Map<
    string,
    { alias: string; canonical: string; aliases: string[] }
  >();

  for (const aliases of Object.values(FIELD_ALIASES)) {
    const canonicalName = aliases[0];
    const uniqueAliases = Array.from(new Set(aliases));
    for (const alias of uniqueAliases) {
      const lower = alias.toLowerCase();
      if (!map.has(lower)) {
        map.set(lower, {
          alias,
          canonical: canonicalName,
          aliases: uniqueAliases,
        });
      }
    }
  }

  return map;
})();

const FIELD_ALIAS_KEYS = Array.from(FIELD_ALIAS_MAP.keys());

const FIELD_SUGGESTIONS: SuggestionItem[] = Array.from(FIELD_ALIAS_MAP.values())
  .map((info) => {
    const description =
      info.alias !== info.canonical ? `Field: ${info.canonical}` : undefined;
    return {
      value: info.alias,
      label: info.alias,
      description,
      kind: "field" as const,
    };
  })
  .sort((a, b) => a.label.localeCompare(b.label));

const OPERATOR_SUGGESTIONS: SuggestionItem[] = [
  { value: "==", label: "==", description: "Equals", kind: "operator" },
  {
    value: "contains",
    label: "contains",
    description: "Substring match",
    kind: "operator",
  },
];

const LOGICAL_SUGGESTIONS: SuggestionItem[] = [
  { value: "&&", label: "&&", description: "Logical AND", kind: "logical" },
  { value: "||", label: "||", description: "Logical OR", kind: "logical" },
  { value: "and", label: "and", description: "AND keyword", kind: "logical" },
  { value: "or", label: "or", description: "OR keyword", kind: "logical" },
  {
    value: "not",
    label: "not",
    description: "Negate the next term",
    kind: "logical",
  },
];

const HISTORY_STORE_KEY = "pipe-lion.filter-history";
const HISTORY_LIMIT = 8;

const historyStore = createStoredList(HISTORY_STORE_KEY, HISTORY_LIMIT);

function hasAliasPrefix(prefix: string) {
  const lowered = prefix.toLowerCase();
  if (!lowered) {
    return false;
  }
  return FIELD_ALIAS_KEYS.some((alias) => alias.startsWith(lowered));
}

function advanceExpectation(
  expectation: SuggestionContext,
  token: FilterTokenWithRange,
): SuggestionContext {
  switch (expectation) {
    case "field": {
      if (token.type === "NOT" || token.type === "LPAREN") {
        return "field";
      }
      if (token.type === "TEXT") {
        const lowered = token.value.toLowerCase();
        if (FIELD_ALIAS_MAP.has(lowered) || hasAliasPrefix(lowered)) {
          return "operator";
        }
        return "logical";
      }
      if (token.type === "RPAREN") {
        return "logical";
      }
      return expectation;
    }
    case "operator": {
      if (token.type === "EQ" || token.type === "CONTAINS") {
        return "value";
      }
      if (token.type === "TEXT") {
        return "logical";
      }
      return expectation;
    }
    case "value": {
      if (token.type === "TEXT") {
        return "logical";
      }
      if (token.type === "LPAREN") {
        return "field";
      }
      return expectation;
    }
    case "logical": {
      if (token.type === "AND" || token.type === "OR") {
        return "field";
      }
      if (token.type === "RPAREN") {
        return "logical";
      }
      if (token.type === "NOT") {
        return "field";
      }
      return expectation;
    }
    default:
      return expectation;
  }
}

function getActiveSegment(value: string, caret: number): ActiveSegment {
  let start = caret;
  while (start > 0) {
    const char = value[start - 1];
    if (/[ \t\n\r()&|!]/.test(char)) {
      break;
    }
    if (char === "=") {
      break;
    }
    start -= 1;
  }
  return { start, text: value.slice(start, caret) };
}

function computeSuggestionContext(
  analysis: FilterAnalysis,
  caret: number,
  segment: ActiveSegment,
): SuggestionContext {
  let expectation: SuggestionContext = "field";

  for (const token of analysis.tokens) {
    if (token.end <= caret) {
      expectation = advanceExpectation(expectation, token);
      continue;
    }

    if (token.start < caret && caret <= token.end) {
      if (token.type === "TEXT") {
        return expectation;
      }
      return expectation;
    }

    break;
  }

  if (expectation === "field" && segment.text) {
    const lowered = segment.text.toLowerCase();
    if (FIELD_ALIAS_MAP.has(lowered) || hasAliasPrefix(lowered)) {
      return "operator";
    }
  }

  return expectation;
}

function filterSuggestions(
  items: SuggestionItem[],
  prefix: string,
  limit = 8,
): SuggestionItem[] {
  const lowered = prefix.toLowerCase();
  const filtered = lowered
    ? items.filter((item) => item.value.toLowerCase().startsWith(lowered))
    : items;
  return filtered.slice(0, limit);
}

function formatErrorMessage(error: FilterSyntaxError | null): string | null {
  if (!error) {
    return null;
  }

  switch (error.message) {
    case "Unexpected '&'":
      return "Use '&&' to join filters with AND.";
    case "Unexpected '|'":
      return "Use '||' to join filters with OR.";
    case "Unexpected '='":
      return "Use '==' for equality comparisons.";
    case "Expected comparison value":
      return "Expected a quoted value after the comparison operator.";
    case "Unexpected trailing tokens":
      return "Remove the trailing text after the filter expression.";
    case "Unexpected token":
      return "Unexpected token in the filter expression.";
    case "Unexpected end of expression":
      return "Incomplete filter expression. Add another term.";
    case "Expected filter term":
      return "Expected a term or field after the operator.";
    case "Unterminated quoted string":
      return "Close the quoted string to finish the value.";
    default:
      return error.message;
  }
}

function ensureSpaceBefore(before: string) {
  if (!before) {
    return false;
  }
  const char = before[before.length - 1];
  return !/[\s(!&|]/.test(char);
}

function ensureSpaceAfter(after: string) {
  if (!after) {
    return true;
  }
  const char = after[0];
  return !/[\s)|&]/.test(char);
}

function buildSuggestions(
  context: SuggestionContext,
  segment: ActiveSegment,
): SuggestionItem[] {
  const prefix = segment.text.trim();

  if (context === "operator") {
    const trimmed = segment.text.trim();
    if (trimmed.length === 0) {
      return filterSuggestions(OPERATOR_SUGGESTIONS, trimmed);
    }
    const fieldMatches = filterSuggestions(FIELD_SUGGESTIONS, trimmed);
    if (fieldMatches.length > 0) {
      return fieldMatches;
    }
    return filterSuggestions(OPERATOR_SUGGESTIONS, trimmed);
  }

  if (context === "logical") {
    return filterSuggestions(LOGICAL_SUGGESTIONS, prefix);
  }

  if (context === "value") {
    return [];
  }

  const fieldSuggestions = filterSuggestions(FIELD_SUGGESTIONS, prefix);
  const includeNot = filterSuggestions(LOGICAL_SUGGESTIONS, prefix).filter(
    (item) => item.value === "not",
  );
  return [...fieldSuggestions, ...includeNot];
}

export type { FilterChangeDetails };

export default function FilterInput({
  id,
  label,
  placeholder,
  describedById,
  value = "",
  onFilterChange,
}: FilterInputProps) {
  const listboxId = useId();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const blurTimeoutRef = useRef<number | null>(null);
  const pendingCaretRef = useRef<number | null>(null);
  const selectionRef = useRef<{ start: number; end: number }>({
    start: value.length,
    end: value.length,
  });

  const [inputValue, setInputValue] = useState(value);
  const [analysis, setAnalysis] = useState<FilterAnalysis>(() =>
    analyzeFilter(value),
  );
  const [caret, setCaret] = useState(value.length);
  const [isFocused, setIsFocused] = useState(false);
  const [isListOpen, setIsListOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [history, setHistory] = useState<string[]>(() => historyStore.load());

  useEffect(() => {
    return () => {
      if (blurTimeoutRef.current !== null) {
        window.clearTimeout(blurTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (value !== inputValue) {
      setInputValue(value);
      setAnalysis(analyzeFilter(value));
      const nextCaret = value.length;
      setCaret(nextCaret);
      selectionRef.current = { start: nextCaret, end: nextCaret };
    }
  }, [value, inputValue]);

  useLayoutEffect(() => {
    if (pendingCaretRef.current !== null && inputRef.current) {
      const next = pendingCaretRef.current;
      inputRef.current.setSelectionRange(next, next);
      pendingCaretRef.current = null;
    }
  }, [inputValue]);

  const segment = useMemo(
    () => getActiveSegment(inputValue, caret),
    [inputValue, caret],
  );

  const suggestionContext = useMemo(
    () => computeSuggestionContext(analysis, caret, segment),
    [analysis, caret, segment],
  );

  const suggestions = useMemo(() => {
    if (!isFocused) {
      return [];
    }
    return buildSuggestions(suggestionContext, segment);
  }, [isFocused, segment, suggestionContext]);

  useEffect(() => {
    setActiveIndex(0);
    if (suggestions.length === 0) {
      setIsListOpen(false);
    } else if (isFocused) {
      setIsListOpen(true);
    }
  }, [suggestions, isFocused]);

  const emitChange = useCallback(
    (text: string, nextCaret?: number) => {
      setInputValue(text);
      const nextAnalysis = analyzeFilter(text);
      setAnalysis(nextAnalysis);
      if (typeof nextCaret === "number") {
        pendingCaretRef.current = nextCaret;
      }

      onFilterChange({
        text,
        ast: nextAnalysis.ast,
        error: nextAnalysis.error,
        errorMessage: formatErrorMessage(nextAnalysis.error),
      });
    },
    [onFilterChange],
  );

  const rememberFilter = useCallback((text: string) => {
    const trimmed = text.trim();
    if (!trimmed) {
      return;
    }
    const next = historyStore.remember(trimmed);
    setHistory(next);
  }, []);

  const handleChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const nextValue = event.target.value;
      const selectionStart = event.target.selectionStart ?? nextValue.length;
      const selectionEnd = event.target.selectionEnd ?? selectionStart;
      selectionRef.current = { start: selectionStart, end: selectionEnd };
      setCaret(selectionEnd);
      emitChange(nextValue, selectionEnd);
      setIsListOpen(true);
    },
    [emitChange],
  );

  const handleSelect = useCallback(
    (event: React.SyntheticEvent<HTMLInputElement>) => {
      const target = event.currentTarget;
      const selectionStart = target.selectionStart ?? 0;
      const selectionEnd = target.selectionEnd ?? selectionStart;
      selectionRef.current = { start: selectionStart, end: selectionEnd };
      setCaret(selectionEnd);
    },
    [],
  );

  const closeSuggestions = useCallback(() => {
    setIsListOpen(false);
  }, []);

  const handleFocus = useCallback(() => {
    setIsFocused(true);
    if (suggestions.length > 0) {
      setIsListOpen(true);
    }
    if (blurTimeoutRef.current !== null) {
      window.clearTimeout(blurTimeoutRef.current);
      blurTimeoutRef.current = null;
    }
  }, [suggestions]);

  const handleBlur = useCallback(() => {
    if (blurTimeoutRef.current !== null) {
      window.clearTimeout(blurTimeoutRef.current);
    }
    blurTimeoutRef.current = window.setTimeout(() => {
      const active = document.activeElement;
      if (!containerRef.current?.contains(active)) {
        setIsFocused(false);
        setIsListOpen(false);
      }
    }, 10);
  }, []);

  const applySuggestion = useCallback(
    (item: SuggestionItem) => {
      const { start, end } = selectionRef.current;
      const caretPosition = end;
      const activeSegment = getActiveSegment(inputValue, caretPosition);
      const replaceFrom = start !== end ? start : activeSegment.start;
      const before = inputValue.slice(0, replaceFrom);
      const after = inputValue.slice(end);

      const needsLeadingSpace = ensureSpaceBefore(before);
      const needsTrailingSpace = ensureSpaceAfter(after);

      let insertion = item.value;
      const context = suggestionContext === "value" ? "value" : item.kind;

      if (context === "operator" || context === "logical") {
        insertion = `${item.value}`;
        if (needsLeadingSpace) {
          insertion = ` ${insertion}`;
        }
        if (needsTrailingSpace) {
          insertion = `${insertion} `;
        }
      } else if (context === "field") {
        if (needsLeadingSpace) {
          insertion = ` ${insertion}`;
        }
        if (needsTrailingSpace) {
          insertion = `${insertion} `;
        }
      }

      const nextValue = `${before}${insertion}${after}`;
      const nextCaret = before.length + insertion.length;
      selectionRef.current = { start: nextCaret, end: nextCaret };
      setCaret(nextCaret);
      emitChange(nextValue, nextCaret);
      setIsListOpen(false);
    },
    [emitChange, inputValue, suggestionContext],
  );

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "ArrowDown" && suggestions.length > 0) {
        event.preventDefault();
        setActiveIndex((index) => (index + 1) % suggestions.length);
        setIsListOpen(true);
        return;
      }

      if (event.key === "ArrowUp" && suggestions.length > 0) {
        event.preventDefault();
        setActiveIndex((index) =>
          index === 0 ? suggestions.length - 1 : index - 1,
        );
        setIsListOpen(true);
        return;
      }

      if (event.key === "Enter") {
        if (isListOpen && suggestions.length > 0) {
          event.preventDefault();
          applySuggestion(suggestions[activeIndex]);
          return;
        }

        if (analysis.ast && !analysis.error && inputValue.trim().length > 0) {
          rememberFilter(inputValue);
        }
        closeSuggestions();
        return;
      }

      if (event.key === "Tab" && isListOpen && suggestions.length > 0) {
        event.preventDefault();
        applySuggestion(suggestions[activeIndex]);
        return;
      }

      if (event.key === "Escape" && isListOpen) {
        event.preventDefault();
        closeSuggestions();
      }
    },
    [
      activeIndex,
      analysis.ast,
      analysis.error,
      applySuggestion,
      closeSuggestions,
      inputValue,
      isListOpen,
      rememberFilter,
      suggestions,
    ],
  );

  const handleSuggestionMouseDown = useCallback((event: React.MouseEvent) => {
    // Prevent blurring the input before selection is applied.
    event.preventDefault();
  }, []);

  const handleSuggestionClick = useCallback(
    (item: SuggestionItem) => {
      applySuggestion(item);
      inputRef.current?.focus();
    },
    [applySuggestion],
  );

  const handleHistorySelect = useCallback(
    (entry: string) => {
      const trimmed = entry.trim();
      const nextCaret = trimmed.length;
      selectionRef.current = { start: nextCaret, end: nextCaret };
      setCaret(nextCaret);
      emitChange(trimmed, nextCaret);
      rememberFilter(trimmed);
      inputRef.current?.focus();
    },
    [emitChange, rememberFilter],
  );

  const errorRange = useMemo(() => {
    if (!analysis.error) {
      return null;
    }
    const start = Math.max(
      0,
      Math.min(analysis.error.start, inputValue.length),
    );
    const end = Math.max(
      start,
      Math.min(analysis.error.end, inputValue.length),
    );
    return { start, end };
  }, [analysis.error, inputValue.length]);

  const beforeError = errorRange
    ? inputValue.slice(0, errorRange.start)
    : inputValue;
  const errorText = errorRange
    ? inputValue.slice(errorRange.start, errorRange.end)
    : "";
  const afterError = errorRange ? inputValue.slice(errorRange.end) : "";

  return (
    <div className="filter-assistant" ref={containerRef}>
      <label className="filter-input" htmlFor={id}>
        <span>{label}</span>
        <div
          className="filter-input-wrapper"
          data-has-error={analysis.error ? "true" : "false"}
        >
          <pre className="filter-input-overlay" aria-hidden="true">
            {errorRange ? (
              <>
                <span>{beforeError}</span>
                <span
                  className="filter-input-error-highlight"
                  data-testid="filter-error-highlight"
                  data-empty={errorText.length === 0 ? "true" : undefined}
                >
                  {errorText.length > 0 ? errorText : "\u00a0"}
                </span>
                <span>{afterError}</span>
              </>
            ) : (
              <span>{inputValue}</span>
            )}
          </pre>
          <input
            ref={inputRef}
            id={id}
            type="text"
            value={inputValue}
            placeholder={placeholder}
            spellCheck={false}
            aria-invalid={analysis.error ? true : false}
            aria-describedby={describedById}
            aria-autocomplete="list"
            aria-expanded={isListOpen}
            aria-controls={
              isListOpen && suggestions.length > 0 ? listboxId : undefined
            }
            aria-activedescendant={
              isListOpen && suggestions[activeIndex]
                ? `${listboxId}-option-${activeIndex}`
                : undefined
            }
            onChange={handleChange}
            onSelect={handleSelect}
            onFocus={handleFocus}
            onBlur={handleBlur}
            onKeyDown={handleKeyDown}
            autoComplete="off"
          />
        </div>
      </label>

      {isListOpen && suggestions.length > 0 ? (
        <ul
          className="filter-suggestions"
          role="listbox"
          id={listboxId}
          onMouseDown={handleSuggestionMouseDown}
        >
          {suggestions.map((item, index) => (
            <li
              key={item.value + index}
              id={`${listboxId}-option-${index}`}
              role="option"
              aria-selected={index === activeIndex}
              className={
                index === activeIndex
                  ? "filter-suggestion active"
                  : "filter-suggestion"
              }
            >
              <button type="button" onClick={() => handleSuggestionClick(item)}>
                <span className="suggestion-label">{item.label}</span>
                {item.description ? (
                  <span className="suggestion-description">
                    {item.description}
                  </span>
                ) : null}
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      {history.length > 0 ? (
        <div className="filter-history" role="list">
          {history.map((entry) => (
            <button
              key={entry}
              type="button"
              className="filter-history-chip"
              onClick={() => handleHistorySelect(entry)}
            >
              {entry}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
