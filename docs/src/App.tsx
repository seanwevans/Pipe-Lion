import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import {
  evaluateFilter,
  parseFilter,
  tokenizeFilter,
  type FilterNode,
  type PacketRecord as FilterPacketRecord,
} from "./filter";
import { loadProcessor, type PacketRecord as WasmPacketRecord } from "./wasm";

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

function toOptionalString(value: unknown): string | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

function toOptionalNumericLike(value: unknown): string | number | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "boolean") {
    return value ? "1" : "0";
  }
  return undefined;
}

function parsePacketSummaryLine(line: string): FilterPacketRecord {
  const trimmed = line.trim();
  const record: FilterPacketRecord = { info: trimmed, summary: trimmed };

  if (trimmed.length === 0) {
    return record;
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return record;
    }

    const data = parsed as Record<string, unknown>;

    const infoValue =
      toOptionalString(data.info) ??
      toOptionalString(data.Info) ??
      toOptionalString(data.summary) ??
      toOptionalString(data.Summary);
    if (infoValue) {
      record.info = infoValue;
    }

    const summaryValue =
      toOptionalString(data.summary) ?? toOptionalString(data.Summary);
    if (summaryValue) {
      record.summary = summaryValue;
    }

    const timeValue =
      toOptionalString(data.time) ??
      toOptionalString(data.timestamp) ??
      toOptionalString(data.Time) ??
      toOptionalString(data.Timestamp);
    if (timeValue) {
      record.time = timeValue;
    }

    const srcValue =
      toOptionalString(data.src) ??
      toOptionalString(data.source) ??
      toOptionalString(data.Source);
    if (srcValue) {
      record.src = srcValue;
      record.source = srcValue;
    }

    const dstValue =
      toOptionalString(data.dst) ??
      toOptionalString(data.destination) ??
      toOptionalString(data.Dst) ??
      toOptionalString(data.Destination);
    if (dstValue) {
      record.dst = dstValue;
      record.destination = dstValue;
    }

    const protocolValue =
      toOptionalString(data.protocol) ??
      toOptionalString(data.proto) ??
      toOptionalString(data.Protocol) ??
      toOptionalString(data.Proto);
    if (protocolValue) {
      record.protocol = protocolValue;
    }

    const lengthValue =
      toOptionalNumericLike(data.length) ??
      toOptionalNumericLike(data.len) ??
      toOptionalNumericLike(data.size) ??
      toOptionalNumericLike(data.Length) ??
      toOptionalNumericLike(data.Len) ??
      toOptionalNumericLike(data.Size);
    if (lengthValue !== undefined) {
      record.length = lengthValue;
    }

    for (const [key, value] of Object.entries(data)) {
      if (value === null || value === undefined) {
        continue;
      }
      if (key in record) {
        continue;
      }
      if (typeof value === "string" || typeof value === "number") {
        record[key] = value;
        continue;
      }
      if (typeof value === "boolean") {
        record[key] = value ? "true" : "false";
      }
    }

    record.summary ??= record.info;
    return record;
  } catch (error) {
    if (import.meta.env.DEV) {
      console.debug("Failed to parse packet summary line", error);
    }
  }

  return record;
}

function toFilterPacketRecord(packet: WasmPacketRecord): FilterPacketRecord {
  const summaryRecord = parsePacketSummaryLine(packet.info);

  return {
    ...summaryRecord,
    time: summaryRecord.time ?? packet.time,
    src: summaryRecord.src ?? packet.source,
    dst: summaryRecord.dst ?? packet.destination,
    protocol: summaryRecord.protocol ?? packet.protocol,
    length: summaryRecord.length ?? packet.length,
    info: summaryRecord.info ?? packet.info,
    summary: summaryRecord.summary ?? summaryRecord.info,
  };
}

type PacketSummaryEntry = {
  packet: WasmPacketRecord;
  record: FilterPacketRecord;
  searchableText: string;
  originalIndex: number;
};

function App() {
  const [status, setStatus] = useState(
    "Drop packet captures or binary payloads to analyze.",
  );

  const [packets, setPackets] = useState<WasmPacketRecord[]>([]);
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<number | null>(
    null,
  );
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
        setPackets([]);
        if (!isMountedRef.current) {
          return;
        }
        setSelectedPacketIndex(null);
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
        const result = processor.process_packet(bytes);
        const processedPackets = Array.isArray(result.packets)
          ? result.packets
          : [];

        if (uploadTokenRef.current !== token) {
          return;
        }
        if (!isMountedRef.current) {
          return;
        }
        setPackets(processedPackets);
        if (!isMountedRef.current) {
          return;
        }
        setSelectedPacketIndex(processedPackets.length > 0 ? 0 : null);
        if (!isMountedRef.current) {
          return;
        }
        const processedCountLabel =
          processedPackets.length === 1 ? "packet" : "packets";
        setStatus(
          processedPackets.length > 0
            ? `Parsed ${processedPackets.length} ${processedCountLabel} from ${file.name}.`
            : `No packets parsed from ${file.name}.`,
        );
        if (!isMountedRef.current) {
          return;
        }
        if (result.errors.length > 0) {
          setError(result.errors.join(" \u2022 "));
        } else if (result.warnings.length > 0) {
          setError(result.warnings.join(" \u2022 "));
        } else {
          setError(null);
        }
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
        setPackets([]);
        if (!isMountedRef.current) {
          return;
        }
        setSelectedPacketIndex(null);
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

  const totalPackets = packets.length;

  const activeFilter =
    filterAst !== null && filterError === null && filterText.trim().length > 0;
  const searchablePackets = useMemo<PacketSummaryEntry[]>(
    () =>
      packets.map((packet, index) => {
        const record = toFilterPacketRecord(packet);
        const searchableText = [
          record.time,
          record.src,
          record.dst,
          record.protocol,
          record.length,
          record.info,
          record.summary,
        ]
          .filter((value): value is string | number => value !== undefined)
          .map((value) => String(value))
          .join(" ")
          .toLowerCase();

        return {
          packet,
          record,
          originalIndex: index,
          searchableText,
        };
      }),
    [packets],
  );
  const visiblePacketEntries = useMemo(() => {
    if (activeFilter && filterAst) {
      return searchablePackets.filter((entry) =>
        evaluateFilter(filterAst, entry.record),
      );
    }
    return searchablePackets;
  }, [activeFilter, filterAst, searchablePackets]);
  const visibleCount = visiblePacketEntries.length;
  const visibleCountLabel = visibleCount === 1 ? "packet" : "packets";
  const totalCountLabel = totalPackets === 1 ? "packet" : "packets";
  const hasPacketData = totalPackets > 0;
  const hasVisiblePackets = visibleCount > 0;
  const visibleIndices = useMemo(
    () => visiblePacketEntries.map((entry) => entry.originalIndex),
    [visiblePacketEntries],
  );

  useEffect(() => {
    if (!hasPacketData) {
      if (selectedPacketIndex !== null) {
        setSelectedPacketIndex(null);
      }
      return;
    }

    if (visibleIndices.length === 0) {
      return;
    }

    if (
      selectedPacketIndex === null ||
      !visibleIndices.includes(selectedPacketIndex)
    ) {
      setSelectedPacketIndex(visibleIndices[0]);
    }
  }, [
    hasPacketData,
    selectedPacketIndex,
    setSelectedPacketIndex,
    visibleIndices,
  ]);

  const selectedPacket =
    selectedPacketIndex !== null ? packets[selectedPacketIndex] ?? null : null;
  const isSelectedPacketVisible =
    selectedPacketIndex !== null &&
    visibleIndices.includes(selectedPacketIndex);
  const displayedPacket = isSelectedPacketVisible ? selectedPacket : null;

  const packetDetailsText = useMemo(() => {
    if (filterError) {
      return "Enter a valid display filter to see matching packets.";
    }
    if (!hasPacketData) {
      return "No packet data loaded.";
    }
    if (!hasVisiblePackets) {
      return activeFilter
        ? "No packets match the current filter."
        : "No packet data loaded.";
    }
    if (!displayedPacket) {
      return "Select a packet to view details.";
    }

    return [
      `Time: ${displayedPacket.time ?? "—"}`,
      `Source: ${displayedPacket.source ?? displayedPacket.src ?? "—"}`,
      `Destination: ${
        displayedPacket.destination ?? displayedPacket.dst ?? "—"
      }`,
      `Protocol: ${displayedPacket.protocol ?? "—"}`,
      `Length: ${
        displayedPacket.length !== undefined
          ? String(displayedPacket.length)
          : "—"
      }`,
      "",
      displayedPacket.info,
    ].join("\n");
  }, [
    activeFilter,
    displayedPacket,
    filterError,
    hasPacketData,
    hasVisiblePackets,
  ]);

  const hexDump = useMemo(() => {
    if (!hasPacketData) {
      return "No data loaded.";
    }
    if (!hasVisiblePackets) {
      return activeFilter
        ? "No packets match the current filter."
        : "No packet data loaded.";
    }

    if (!displayedPacket) {
      return "Select a packet to view its payload.";
    }
    const payload = displayedPacket.payload;
    if (!payload || payload.length === 0) {
      return "Packet payload is empty.";
    }

    return formatHex(payload);
  }, [activeFilter, displayedPacket, hasPacketData, hasVisiblePackets]);

  const showDropOverlay = dragActive || !hasPacketData;

  const onPacketTableKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (visibleIndices.length === 0) {
        return;
      }

      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const currentPosition =
          selectedPacketIndex !== null
            ? visibleIndices.indexOf(selectedPacketIndex)
            : -1;

        if (event.key === "ArrowDown") {
          const nextPosition =
            currentPosition === -1
              ? 0
              : Math.min(currentPosition + 1, visibleIndices.length - 1);
          setSelectedPacketIndex(visibleIndices[nextPosition]);
        } else {
          const nextPosition =
            currentPosition === -1
              ? visibleIndices.length - 1
              : Math.max(currentPosition - 1, 0);
          setSelectedPacketIndex(visibleIndices[nextPosition]);
        }
      }
    },
    [selectedPacketIndex, setSelectedPacketIndex, visibleIndices],
  );

  return (
    <div className="app">
      <input
        ref={fileInputRef}
        id="file-input"
        type="file"
        accept=".pcap,.pcapng,.bin,.dat,.raw,.txt,application/octet-stream"
        multiple
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
              aria-describedby={
                filterError ? "display-filter-error" : undefined
              }
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
              tabIndex={0}
              onKeyDown={onPacketTableKeyDown}
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
                  visiblePacketEntries.map(({ packet, record, originalIndex }) => {
                    const isSelected = originalIndex === selectedPacketIndex;
                    return (
                      <div
                        className={`table-row${isSelected ? " selected" : ""}`}
                        role="row"
                        key={`packet-${originalIndex}`}
                        tabIndex={0}
                        data-selected={isSelected || undefined}
                        aria-selected={isSelected}
                        onClick={() => setSelectedPacketIndex(originalIndex)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedPacketIndex(originalIndex);
                          }
                        }}
                      >
                        <span role="cell">{originalIndex + 1}</span>
                        <span role="cell">{packet.time}</span>
                        <span role="cell">{packet.source}</span>
                        <span role="cell">{packet.destination}</span>
                        <span role="cell">{packet.protocol}</span>
                        <span role="cell">{packet.length}</span>
                        <span role="cell" className="info-cell">
                          {record.info}
                        </span>
                      </div>
                    );
                  })
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

          {showDropOverlay && (
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
