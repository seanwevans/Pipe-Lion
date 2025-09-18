import { useCallback, useEffect, useRef, useState } from "react";
import "./App.css";
import { loadProcessor } from "./wasm";

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
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const processingQueueRef = useRef<Promise<void>>(Promise.resolve());
  const uploadTokenRef = useRef(0);

  useEffect(() => {
    loadProcessor()
      .then(() => {
        setIsReady(true);
        setStatus("Drop packet captures or binary payloads to analyze.");
      })
      .catch((err) => {
        console.error("Failed to load Wasm module", err);
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
        setError(
          `${file.name} is ${formattedFileSize} MB, which exceeds the configured limit of ${maxFileSizeMB} MB.`,
        );
        setStatus("Choose a smaller file or increase the max file size limit.");
        setPacketSummary("Awaiting packet data.");
        setHexDump("No data loaded.");
        return;
      }

      setStatus(`Processing ${file.name} (${file.size} bytes)…`);
      setError(null);

      try {
        const buffer = await file.arrayBuffer();
        if (uploadTokenRef.current !== token) {
          return;
        }
        const bytes = new Uint8Array(buffer);
        const processor = await loadProcessor();
        if (uploadTokenRef.current !== token) {
          return;
        }
        const summary = processor.process_packet(bytes);

        if (uploadTokenRef.current !== token) {
          return;
        }
        setPacketSummary(summary);
        setHexDump(formatHex(bytes));
        setStatus(`Processed ${file.name}.`);
        setError(null);
      } catch (err) {
        console.error("Processing failed", err);
        if (uploadTokenRef.current !== token) {
          return;
        }
        setError("Failed to process the uploaded file.");

        setStatus("Drop a packet capture or binary payload to analyze.");
        setPacketSummary("Awaiting packet data.");
        setHexDump("No data loaded.");
      }
    },
    [maxFileSizeMB],
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

  const summaryLines = packetSummary
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const hasPacketData = summaryLines.length > 0;
  const hasHexData = hexDump !== "No data loaded.";

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
            <button
              type="button"
              onClick={onBrowseClick}
              disabled={!isReady}
            >
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
              disabled
            />
          </label>
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
                Showing {hasPacketData ? summaryLines.length : 0} entries
              </span>
            </header>
            <div className="packet-table" role="table" aria-label="Captured packets">
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
                summaryLines.map((line, index) => (
                  <div className="table-row" role="row" key={`${line}-${index}`}>
                    <span role="cell">{index + 1}</span>
                    <span role="cell">—</span>
                    <span role="cell">—</span>
                    <span role="cell">—</span>
                    <span role="cell">—</span>
                    <span role="cell">—</span>
                    <span role="cell" className="info-cell">
                      {line}
                    </span>
                  </div>
                ))
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
            <pre>{packetSummary}</pre>
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
