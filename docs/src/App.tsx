import { useCallback, useEffect, useRef, useState } from "react";
import "./App.css";
import { loadProcessor } from "./wasm";

type FilterNode =
  | { type: "text"; value: string }
  | { type: "and"; left: FilterNode; right: FilterNode }
  | { type: "or"; left: FilterNode; right: FilterNode }
  | { type: "not"; operand: FilterNode };

type FilterToken =
  | { type: "LPAREN" }
  | { type: "RPAREN" }
  | { type: "AND" }
  | { type: "OR" }
  | { type: "NOT" }
  | { type: "TEXT"; value: string };

function tokenizeFilter(expression: string): FilterToken[] {
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

function parseFilter(tokens: FilterToken[]): FilterNode {
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

function evaluateFilter(node: FilterNode, line: string): boolean {
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

const BYTE_TO_HEX = (() => {
  const table = new Array<string>(256);
  for (let i = 0; i < 256; i += 1) {
    table[i] = i.toString(16).padStart(2, "0");
  }
  return table;
})();

function formatHex(data: Uint8Array, bytesPerRow = 16, maxRows = 32): string {
  if (data.length === 0) {
    return "No data loaded.";
  }

  const lines: string[] = [];
  const maxBytes = bytesPerRow * maxRows;
  const view = data.subarray(0, Math.min(maxBytes, data.length));
  const hexPadLength = bytesPerRow * 3 - 1;

  for (let offset = 0; offset < view.length; offset += bytesPerRow) {
    const rowLength = Math.min(bytesPerRow, view.length - offset);
    let hexLine = "";
    let asciiLine = "";

    for (let index = 0; index < rowLength; index += 1) {
      const byte = view[offset + index];
      const hex = BYTE_TO_HEX[byte];
      hexLine += index === 0 ? hex : ` ${hex}`;
      asciiLine +=
        byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
    }

    lines.push(
      `${offset.toString(16).padStart(8, "0")}  ${hexLine.padEnd(
        hexPadLength,
        " ",
      )}  |${asciiLine}|`,
    );
  }

  if (data.length > maxBytes) {
    lines.push(`… (${data.length - maxBytes} more bytes)`); // ellipsis
  }

  return lines.join("\n");
}

const BYTES_PER_MEGABYTE = 1024 * 1024;
const DEFAULT_MAX_FILE_SIZE_MB = 25;
const MIN_FILE_SIZE_MB = 1;
const MAX_FILE_SIZE_MB = 500;

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

function App() {
  const [status, setStatus] = useState(
    "Drop packet captures or binary payloads to analyze.",
  );
  const [packetSummary, setPacketSummary] = useState("Awaiting packet data.");
  const [hexDump, setHexDump] = useState("No data loaded.");
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [maxFileSizeMB, setMaxFileSizeMB] = useState(DEFAULT_MAX_FILE_SIZE_MB);
  const [filterText, setFilterText] = useState("");
  const [filterAst, setFilterAst] = useState<FilterNode | null>(null);
  const [filterError, setFilterError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const processingQueueRef = useRef<Promise<void>>(Promise.resolve());
  const uploadTokenRef = useRef(0);
  const isMountedRef = useRef(true);
  const fileReaderRef = useRef<FileReader | null>(null);

  const abortActiveReader = useCallback(() => {
    const activeReader = fileReaderRef.current;
    if (activeReader) {
      activeReader.abort();
      fileReaderRef.current = null;
    }
  }, []);

  const readFileBytes = useCallback(
    (file: File) =>
      new Promise<Uint8Array>((resolve, reject) => {
        abortActiveReader();

        const reader = new FileReader();
        fileReaderRef.current = reader;

        reader.onload = () => {
          fileReaderRef.current = null;
          const result = reader.result;
          if (result instanceof ArrayBuffer) {
            resolve(new Uint8Array(result));
            return;
          }

          reject(new Error("Unexpected file reader result."));
        };

        reader.onerror = () => {
          fileReaderRef.current = null;
          reject(reader.error ?? new Error("Failed to read file."));
        };

        reader.onabort = () => {
          fileReaderRef.current = null;
          reject(new DOMException("Aborted", "AbortError"));
        };

        reader.readAsArrayBuffer(file);
      }),
    [abortActiveReader],
  );

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      uploadTokenRef.current += 1;
      abortActiveReader();
    };
  }, [abortActiveReader]);

  useEffect(() => {
    loadProcessor()
      .then(() => {
        if (!isMountedRef.current) {
          return;
        }
        setIsReady(true);
        setStatus("Drop packet captures or binary payloads to analyze.");
      })
      .catch((err) => {
        console.error("Failed to load Wasm module", err);
        if (!isMountedRef.current) {
          return;
        }
        setError("Unable to load the WebAssembly packet processor.");
        setStatus("Reload the page or check the Wasm build output.");
      });
  }, []);

  const handleFile = useCallback(
    async (file: File) => {
      const token = ++uploadTokenRef.current;
      const maxBytes = maxFileSizeMB * BYTES_PER_MEGABYTE;
      if (file.size > maxBytes) {
        const fileSizeMB = file.size / BYTES_PER_MEGABYTE;
        const formattedFileSize = fileSizeMB.toFixed(fileSizeMB >= 10 ? 0 : 2);
        if (!isMountedRef.current) {
          return;
        }
        setError(
          `${file.name} is ${formattedFileSize} MB, which exceeds the configured limit of ${maxFileSizeMB} MB.`,
        );
        if (!isMountedRef.current) {
          return;
        }
        setStatus("Choose a smaller file or increase the max file size limit.");
        if (!isMountedRef.current) {
          return;
        }
        setPacketSummary("Awaiting packet data.");
        if (!isMountedRef.current) {
          return;
        }
        setHexDump("No data loaded.");
        return;
      }

      if (!isMountedRef.current) {
        return;
      }
      setStatus(`Processing ${file.name} (${file.size} bytes)…`);
      if (!isMountedRef.current) {
        return;
      }
      setError(null);

      try {
        const bytes = await readFileBytes(file);
        if (uploadTokenRef.current !== token) {
          return;
        }
        const processor = await loadProcessor();
        if (uploadTokenRef.current !== token) {
          return;
        }
        const summary = processor.process_packet(bytes);

        if (uploadTokenRef.current !== token) {
          return;
        }
        if (!isMountedRef.current) {
          return;
        }
        setPacketSummary(summary);
        if (!isMountedRef.current) {
          return;
        }
        setHexDump(formatHex(bytes));
        if (!isMountedRef.current) {
          return;
        }
        setStatus(`Processed ${file.name}.`);
        if (!isMountedRef.current) {
          return;
        }
        setError(null);
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") {
          return;
        }
        console.error("Processing failed", err);
        if (uploadTokenRef.current !== token) {
          return;
        }
        if (!isMountedRef.current) {
          return;
        }
        setError("Failed to process the uploaded file.");

        if (!isMountedRef.current) {
          return;
        }
        setStatus("Drop a packet capture or binary payload to analyze.");
        if (!isMountedRef.current) {
          return;
        }
        setPacketSummary("Awaiting packet data.");
        if (!isMountedRef.current) {
          return;
        }
        setHexDump("No data loaded.");
      }
    },
    [maxFileSizeMB, readFileBytes],
  );

  const enqueueFile = useCallback(
    (file: File) => {
      processingQueueRef.current = processingQueueRef.current
        .then(() => handleFile(file))
        .catch((err) => {
          console.error("Queued file processing failed", err);
        });
      return processingQueueRef.current;
    },
    [handleFile],
  );

  const onDrop = useCallback(
    async (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragActive(false);
      const files = Array.from(event.dataTransfer.files ?? []);
      for (const file of files) {
        await enqueueFile(file);
      }
    },
    [enqueueFile],
  );

  const onDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    setDragActive(true);
  }, []);

  const onDragLeave = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    const related = event.relatedTarget as Node | null;
    if (related && event.currentTarget.contains(related)) {
      return;
    }
    setDragActive(false);
  }, []);

  const onFileChange = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const input = event.target;
      const files = Array.from(input.files ?? []);
      for (const file of files) {
        await enqueueFile(file);
      }
      input.value = "";
    },
    [enqueueFile],
  );

  const onBrowseClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const onMaxFileSizeChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const parsedValue = Number(event.target.value);
      if (Number.isNaN(parsedValue)) {
        return;
      }

      const clampedValue = clamp(
        parsedValue,
        MIN_FILE_SIZE_MB,
        MAX_FILE_SIZE_MB,
      );
      setMaxFileSizeMB(clampedValue);
    },
    [],
  );

  const onFilterChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const value = event.target.value;
      setFilterText(value);

      const trimmed = value.trim();
      if (trimmed.length === 0) {
        setFilterAst(null);
        setFilterError(null);
        return;
      }

      try {
        const tokens = tokenizeFilter(value);
        if (tokens.length === 0) {
          setFilterAst(null);
          setFilterError(null);
          return;
        }
        const node = parseFilter(tokens);
        setFilterAst(node);
        setFilterError(null);
      } catch (err) {
        console.debug("Failed to parse display filter", err);
        setFilterAst(null);
        setFilterError(
          "Invalid display filter. Use AND/OR/NOT with parentheses or quotes.",
        );
      }
    },
    [],
  );

  const summaryLines = packetSummary
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const awaitingPlaceholder =
    summaryLines.length === 1 && summaryLines[0] === "Awaiting packet data.";
  const baseSummaryLines = awaitingPlaceholder ? [] : summaryLines;
  const baseSummaryEntries = baseSummaryLines.map((text, index) => ({
    text,
    originalIndex: index,
  }));
  const totalPackets = baseSummaryEntries.length;
  const activeFilter =
    filterAst !== null && filterError === null && filterText.trim().length > 0;
  const visibleSummaryEntries =
    activeFilter && filterAst
      ? baseSummaryEntries.filter((entry) =>
          evaluateFilter(filterAst, entry.text.toLowerCase()),
        )
      : baseSummaryEntries;
  const visibleCount = visibleSummaryEntries.length;
  const visibleCountLabel = visibleCount === 1 ? "packet" : "packets";
  const totalCountLabel = totalPackets === 1 ? "packet" : "packets";
  const hasPacketData = totalPackets > 0;
  const hasVisiblePackets = visibleCount > 0;
  const hasHexData = hexDump !== "No data loaded.";
  const packetDetailsText = (() => {
    if (awaitingPlaceholder) {
      return "Awaiting packet data.";
    }
    if (filterError) {
      return "Enter a valid display filter to see matching packets.";
    }
    if (!hasPacketData) {
      return "No packet details available.";
    }
    if (!hasVisiblePackets) {
      return activeFilter
        ? "No packets match the current filter."
        : "No packet details available.";
    }
    return visibleSummaryEntries.map((entry) => entry.text).join("\n");
  })();

  return (
    <div className="app">
      <input
        ref={fileInputRef}
        id="file-input"
        type="file"
        accept=".pcap,.pcapng,.bin,.dat,.raw,.txt,application/octet-stream"
        onChange={onFileChange}
        hidden
      />

      <div className="window">
        <div className="window-top-bar">
          <div className="window-controls" aria-hidden="true">
            <span className="control-dot control-close" />
            <span className="control-dot control-minimize" />
            <span className="control-dot control-zoom" />
          </div>
          <h1 className="window-title">Pipe-Lion Packet Playground</h1>
          <span
            className="status-chip"
            data-ready={isReady}
            role="status"
            aria-live="polite"
          >
            {status}
          </span>
        </div>

        <nav className="menu-bar" aria-label="Application menu">
          <button type="button">File</button>
          <button type="button">Edit</button>
          <button type="button">View</button>
          <button type="button">Go</button>
          <button type="button">Capture</button>
          <button type="button">Analyze</button>
          <button type="button">Statistics</button>
          <button type="button">Telephony</button>
          <button type="button">Wireless</button>
          <button type="button">Tools</button>
          <button type="button">Help</button>
        </nav>

        <div className="toolbar">
          <div className="toolbar-buttons">
            <button type="button" onClick={onBrowseClick} disabled={!isReady}>
              Open Capture…
            </button>
            <button type="button" disabled>
              Save As…
            </button>
            <button type="button" disabled>
              Restart Capture
            </button>
          </div>
          {error ? (
            <div className="toolbar-error" role="alert" aria-live="assertive">
              {error}
            </div>
          ) : (
            <div className="toolbar-hint">
              Max file size can be adjusted in the filter bar.
            </div>
          )}
        </div>

        <div className="filter-bar">
          <label className="filter-input" htmlFor="display-filter">
            <span>Display filter</span>
            <input
              id="display-filter"
              type="text"
              placeholder="tcp && http"
              spellCheck={false}
              value={filterText}
              onChange={onFilterChange}
              aria-invalid={filterError ? true : false}
              aria-describedby={filterError ? "display-filter-error" : undefined}
            />
          </label>
          <div className="filter-right">
            <div className="filter-meta" aria-live="polite">
              {filterError ? (
                <span
                  id="display-filter-error"
                  className="filter-error"
                  role="alert"
                >
                  {filterError}
                </span>
              ) : (
                <span className="filter-count">
                  {activeFilter
                    ? `Showing ${visibleCount} ${visibleCountLabel} of ${totalPackets} ${totalCountLabel}`
                    : `Showing ${totalPackets} ${totalCountLabel}`}
                </span>
              )}
            </div>
            <div className="filter-controls">
              <label htmlFor="max-file-size">Max file size (MB)</label>
              <input
                id="max-file-size"
                type="number"
                min={MIN_FILE_SIZE_MB}
                max={MAX_FILE_SIZE_MB}
                step={1}
                value={maxFileSizeMB}
                onChange={onMaxFileSizeChange}
                disabled={!isReady}
              />
            </div>
          </div>
        </div>

        <div
          className={`workspace${dragActive ? " dragging" : ""}`}
          onDrop={onDrop}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
        >
          <section className="pane packet-list" aria-label="Packet list">
            <header>
              <h2>Packet List</h2>
              <span className="pane-subtitle">
                Showing {visibleCount}
                {activeFilter ? ` of ${totalPackets}` : ""} entries
              </span>
            </header>
            <div
              className="packet-table"
              role="table"
              aria-label="Captured packets"
            >
              <div className="table-row table-header" role="row">
                <span role="columnheader">No.</span>
                <span role="columnheader">Time</span>
                <span role="columnheader">Source</span>
                <span role="columnheader">Destination</span>
                <span role="columnheader">Protocol</span>
                <span role="columnheader">Length</span>
                <span role="columnheader">Info</span>
              </div>
              {hasPacketData ? (
                hasVisiblePackets ? (
                  visibleSummaryEntries.map(({ text, originalIndex }) => (
                    <div
                      className="table-row"
                      role="row"
                      key={`${originalIndex}-${text}`}
                    >
                      <span role="cell">{originalIndex + 1}</span>
                      <span role="cell">—</span>
                      <span role="cell">—</span>
                      <span role="cell">—</span>
                      <span role="cell">—</span>
                      <span role="cell">—</span>
                      <span role="cell" className="info-cell">
                        {text}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="table-row empty" role="row">
                    <span role="cell" className="info-cell">
                      No packets match the current filter.
                    </span>
                  </div>
                )
              ) : (
                <div className="table-row empty" role="row">
                  <span role="cell" className="info-cell">
                    Drop a capture to populate the packet list.
                  </span>
                </div>
              )}
            </div>
          </section>

          <section className="pane packet-details" aria-label="Packet details">
            <header>
              <h2>Packet Details</h2>
              <span className="pane-subtitle">Summary of parsed metadata</span>
            </header>
            <pre>{packetDetailsText}</pre>
          </section>

          <section className="pane packet-bytes" aria-label="Packet bytes">
            <header>
              <h2>Packet Bytes</h2>
              <span className="pane-subtitle">Hex &amp; ASCII</span>
            </header>
            <pre>{hexDump}</pre>
          </section>

          {(dragActive || (!hasPacketData && !hasHexData)) && (
            <div
              className={`drop-overlay${dragActive ? " active" : ""}`}
              role="button"
              tabIndex={0}
              onClick={onBrowseClick}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onBrowseClick();
                }
              }}
            >
              <div className="drop-overlay__content">
                <p className="drop-overlay__title">
                  Drop packet captures or binary payloads to analyze
                </p>
                <button type="button" disabled={!isReady}>
                  Browse files
                </button>
                <p className="drop-overlay__hint">
                  Supported: pcap, pcapng, bin, dat, raw, txt
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
