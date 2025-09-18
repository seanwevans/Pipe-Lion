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
    "Drop a packet capture or binary payload to analyze.",
  );
  const [packetSummary, setPacketSummary] = useState("Awaiting packet data.");
  const [hexDump, setHexDump] = useState("No data loaded.");
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [maxFileSizeMB, setMaxFileSizeMB] = useState(DEFAULT_MAX_FILE_SIZE_MB);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    loadProcessor()
      .then(() => {
        setIsReady(true);
        setStatus("Drop a packet capture or binary payload to analyze.");
      })
      .catch((err) => {
        console.error("Failed to load Wasm module", err);
        setError("Unable to load the WebAssembly packet processor.");
        setStatus("Reload the page or check the Wasm build output.");
      });
  }, []);

  const handleFile = useCallback(
    async (file: File) => {
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
        const bytes = new Uint8Array(buffer);
        const processor = await loadProcessor();
        const summary = processor.process_packet(bytes);

        setPacketSummary(summary);
        setHexDump(formatHex(bytes));
        setStatus(`Processed ${file.name}.`);
        setError(null);
      } catch (err) {
        console.error("Processing failed", err);
        setError("Failed to process the uploaded file.");
        setStatus("Drop a packet capture or binary payload to analyze.");
        setPacketSummary("Awaiting packet data.");
        setHexDump("No data loaded.");
      }
    },
    [maxFileSizeMB],
  );

  const onDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragActive(false);
      const file = event.dataTransfer.files?.[0];
      if (file) {
        void handleFile(file);
      }
    },
    [handleFile],
  );

  const onDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    setDragActive(true);
  }, []);

  const onDragLeave = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragActive(false);
  }, []);

  const onFileChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (file) {
        void handleFile(file);
        event.target.value = "";
      }
    },
    [handleFile],
  );

  const onBrowseClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const onDropZoneKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        onBrowseClick();
      }
    },
    [onBrowseClick],
  );

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

  return (
    <div className="app">
      <header className="header">
        <h1>Pipe-Lion Packet Playground</h1>
        <p className="tagline">
          Experiment with WebAssembly-powered packet parsing.
        </p>
        <p
          className="status"
          data-ready={isReady}
          role="status"
          aria-live="polite"
        >
          {status}
        </p>
      </header>

      <section
        className={`drop-zone${dragActive ? " active" : ""}`}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onKeyDown={onDropZoneKeyDown}
        role="button"
        tabIndex={0}
      >
        <input
          ref={fileInputRef}
          id="file-input"
          type="file"
          accept=".pcap,.pcapng,.bin,.dat,.raw,.txt,application/octet-stream"
          onChange={onFileChange}
          hidden
        />
        <p className="drop-label">Drag &amp; drop files here</p>
        <p className="drop-sub">or</p>
        <button
          className="browse-button"
          type="button"
          onClick={onBrowseClick}
          disabled={!isReady}
        >
          Browse files
        </button>
      </section>

      <section className="settings">
        <label className="settings__item" htmlFor="max-file-size">
          <span>Max file size (MB)</span>
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
        </label>
      </section>

      {error && (
        <div className="error" role="alert" aria-live="assertive">
          {error}
        </div>
      )}

      <section className="panes">
        <article className="pane">
          <h2>Packet Summary</h2>
          <pre>{packetSummary}</pre>
        </article>
        <article className="pane">
          <h2>Hex Preview</h2>
          <pre>{hexDump}</pre>
        </article>
      </section>
    </div>
  );
}

export default App;
