import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import App from "./App";
import * as storage from "./storage";

const { captureMock, loadProcessorMock, freeMock, filterMock } = vi.hoisted(
  () => ({
    captureMock: vi.fn(),
    loadProcessorMock: vi.fn(),
    freeMock: vi.fn(),
    filterMock: vi.fn(),
  }),
);

type MockPacket = Record<string, unknown> & { payload?: Uint8Array };
type MockCapture = {
  packets: MockPacket[];
  warnings: string[];
  errors: string[];
};

/// Stands in for a real `CaptureHandle`: rows come back a window at a time and
/// payloads one packet at a time, so the tests exercise the same access pattern
/// the Wasm boundary imposes.
const mockProcessor = {
  parse: (data: Uint8Array) => {
    const capture = captureMock(data) as MockCapture;
    const rows = capture.packets.map((packet, index) => ({
      index,
      hex_preview: "",
      ascii_preview: "",
      payload_length: packet.payload?.length ?? 0,
      ...packet,
    }));

    return {
      packetCount: rows.length,
      warnings: capture.warnings,
      errors: capture.errors,
      packets: (offset: number, count: number) =>
        rows.slice(offset, offset + count),
      payload: (index: number) =>
        capture.packets[index]?.payload ?? new Uint8Array(),
      // Stands in for the core's evaluator: a naive scan of the row, which is
      // enough to prove App delegates filtering rather than doing it itself.
      filter: (expression: string) => {
        filterMock(expression);
        const needle = expression.trim().toLowerCase();
        return Uint32Array.from(
          rows
            .map((row, index) => ({ row, index }))
            .filter(({ row }) =>
              JSON.stringify(row).toLowerCase().includes(needle),
            )
            .map(({ index }) => index),
        );
      },
      free: freeMock,
    };
  },
};

vi.mock("./wasm", () => ({
  loadProcessor: loadProcessorMock,
}));

type FileReaderHandler =
  | ((this: FileReader, event: ProgressEvent<FileReader>) => unknown)
  | null;

class ControlledFileReader implements Partial<FileReader> {
  public onload: FileReaderHandler = null;
  public onerror: FileReaderHandler = null;
  public onabort: FileReaderHandler = null;
  public result: string | ArrayBuffer | null = null;
  public error: DOMException | null = null;
  private aborted = false;

  readAsArrayBuffer(_file: File) {
    activeReaders.push(this);
  }

  abort() {
    if (this.aborted) {
      return;
    }
    this.aborted = true;
    this.result = null;
    const event = new ProgressEvent("abort") as ProgressEvent<FileReader>;
    this.onabort?.call(this as unknown as FileReader, event);
  }

  async emitLoad(data?: ArrayBuffer) {
    if (this.aborted) {
      return;
    }
    const buffer = data ?? new ArrayBuffer(4);
    this.result = buffer;
    const event = new ProgressEvent("load") as ProgressEvent<FileReader>;
    this.onload?.call(this as unknown as FileReader, event);
  }
}

const activeReaders: ControlledFileReader[] = [];
const OriginalFileReader = globalThis.FileReader;

function firstEnabled(buttons: HTMLElement[]): HTMLElement {
  const button = buttons.find(
    (candidate) => !candidate.hasAttribute("disabled"),
  );
  if (!button) {
    throw new Error("Expected at least one enabled button");
  }
  return button;
}

describe("App restart flow", () => {
  beforeEach(() => {
    activeReaders.length = 0;
    // App restores the filter and size preferences from localStorage on mount,
    // so tests leak into each other unless it starts empty.
    globalThis.localStorage?.clear();
    captureMock.mockReset();
    freeMock.mockReset();
    filterMock.mockReset();
    loadProcessorMock.mockReset();
    loadProcessorMock.mockResolvedValue(mockProcessor);
    globalThis.FileReader =
      ControlledFileReader as unknown as typeof FileReader;
  });

  afterEach(() => {
    cleanup();
  });

  afterAll(() => {
    globalThis.FileReader = OriginalFileReader;
  });

  it("resets the workspace to its initial state", async () => {
    const user = userEvent.setup();

    captureMock.mockImplementation(() => ({
      packets: [
        {
          time: "0.000001",
          source: "1.1.1.1",
          destination: "2.2.2.2",
          protocol: "TEST",
          length: 4,
          info: "Synthetic packet",
          payload: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
        },
      ],
      warnings: [],
      errors: ["Processing issue"],
    }));

    render(<App />);

    const restartButtons = await screen.findAllByRole("button", {
      name: "Restart Capture",
    });
    const restartButton = firstEnabled(restartButtons);
    await waitFor(() => expect(restartButton).toBeEnabled());

    const statusChip = screen.getByRole("status");
    expect(statusChip).toHaveTextContent(
      "Drop packet captures or binary payloads to analyze.",
    );

    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    const file = new File([Uint8Array.from([0x01, 0x02])], "example.pcap", {
      type: "application/octet-stream",
    });
    fireEvent.change(fileInput, { target: { files: [file] } });

    await waitFor(() =>
      expect(statusChip).toHaveTextContent(
        "Processing example.pcap (2 bytes)…",
      ),
    );

    await waitFor(() => expect(activeReaders.length).toBeGreaterThan(0));
    const activeReader = activeReaders[0];
    expect(activeReader).toBeDefined();
    await activeReader?.emitLoad();

    await waitFor(() => expect(captureMock).toHaveBeenCalledTimes(1));

    await waitFor(() =>
      expect(statusChip).toHaveTextContent(
        "Parsed 1 packet from example.pcap.",
      ),
    );

    const errorBanner = await screen.findByRole("alert");
    expect(errorBanner).toHaveTextContent("Fatal parse errors");
    expect(errorBanner).toHaveTextContent("Processing issue");
    expect(
      screen.queryByText("Drop a capture to populate the packet list."),
    ).not.toBeInTheDocument();

    await user.click(restartButton);

    await waitFor(() =>
      expect(statusChip).toHaveTextContent(
        "Drop packet captures or binary payloads to analyze.",
      ),
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.getByText("Drop a capture to populate the packet list."),
    ).toBeInTheDocument();
    expect(screen.getByText("No packet data loaded.")).toBeInTheDocument();
  });

  it("delegates display filtering to the core", async () => {
    const user = userEvent.setup();

    captureMock.mockImplementation(() => ({
      packets: [
        {
          time: "0.000001",
          source: "1.1.1.1",
          destination: "2.2.2.2",
          protocol: "TEST",
          length: 4,
          info: "Synthetic packet",
          payload: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
        },
      ],
      warnings: [],
      errors: [],
    }));

    render(<App />);

    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: { files: [new File([Uint8Array.from([0x01])], "one.pcap")] },
    });

    await waitFor(() => expect(activeReaders.length).toBeGreaterThan(0));
    await activeReaders[0]?.emitLoad();
    await screen.findByText("Synthetic packet");

    await user.type(screen.getByLabelText("Display filter"), "nomatch");

    await waitFor(() =>
      expect(filterMock).toHaveBeenCalledWith(expect.stringContaining("n")),
    );
    expect(
      (await screen.findAllByText("No packets match the current filter."))
        .length,
    ).toBeGreaterThan(0);
  });

  it("frees the previous capture when the workspace is reset", async () => {
    const user = userEvent.setup();

    captureMock.mockImplementation(() => ({
      packets: [
        {
          time: "0.000001",
          source: "1.1.1.1",
          destination: "2.2.2.2",
          protocol: "TEST",
          length: 4,
          info: "Synthetic packet",
          payload: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
        },
      ],
      warnings: [],
      errors: [],
    }));

    render(<App />);

    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: { files: [new File([Uint8Array.from([0x01])], "one.pcap")] },
    });

    await waitFor(() => expect(activeReaders.length).toBeGreaterThan(0));
    await activeReaders[0]?.emitLoad();
    await waitFor(() => expect(captureMock).toHaveBeenCalledTimes(1));
    expect(freeMock).not.toHaveBeenCalled();

    const restartButton = firstEnabled(
      await screen.findAllByRole("button", { name: "Restart Capture" }),
    );
    await user.click(restartButton);

    await waitFor(() => expect(freeMock).toHaveBeenCalledTimes(1));
  });

  it("prevents stale packets from reappearing after restart", async () => {
    const user = userEvent.setup();

    captureMock.mockImplementation(() => ({
      packets: [
        {
          time: "0.000001",
          source: "1.1.1.1",
          destination: "2.2.2.2",
          protocol: "TEST",
          length: 1,
          info: "Queued packet",
          payload: Uint8Array.from([0x99]),
        },
      ],
      warnings: [],
      errors: [],
    }));

    render(<App />);

    const restartButtons = await screen.findAllByRole("button", {
      name: "Restart Capture",
    });
    const restartButton = firstEnabled(restartButtons);
    await waitFor(() => expect(restartButton).toBeEnabled());
    const statusChip = screen.getByRole("status");

    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    const firstFile = new File([Uint8Array.from([0x01])], "first.pcap", {
      type: "application/octet-stream",
    });
    fireEvent.change(fileInput, { target: { files: [firstFile] } });

    await waitFor(() =>
      expect(statusChip).toHaveTextContent("Processing first.pcap (1 bytes)…"),
    );
    expect(captureMock).not.toHaveBeenCalled();

    const secondFile = new File([Uint8Array.from([0x02])], "second.pcap", {
      type: "application/octet-stream",
    });
    fireEvent.change(fileInput, { target: { files: [secondFile] } });

    await waitFor(() => expect(activeReaders.length).toBeGreaterThan(0));

    await user.click(restartButton);

    await waitFor(() =>
      expect(statusChip).toHaveTextContent(
        "Drop packet captures or binary payloads to analyze.",
      ),
    );
    expect(captureMock).not.toHaveBeenCalled();

    await Promise.all(activeReaders.map((reader) => reader.emitLoad()));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(captureMock).not.toHaveBeenCalled();
    expect(
      screen.getByText("Drop a capture to populate the packet list."),
    ).toBeInTheDocument();
  });

  it("shows non-blocking hint when preference persistence fails", async () => {
    const user = userEvent.setup();
    vi.spyOn(storage, "saveFilterText").mockReturnValue(false);

    render(<App />);

    const filterInput = await screen.findByLabelText("Display filter");
    await user.type(filterInput, "tcp");

    expect(
      await screen.findByText("Preferences not persisted."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("Diagnostics panel", () => {
  beforeEach(() => {
    activeReaders.length = 0;
    // App restores the filter and size preferences from localStorage on mount,
    // so tests leak into each other unless it starts empty.
    globalThis.localStorage?.clear();
    captureMock.mockReset();
    freeMock.mockReset();
    filterMock.mockReset();
    loadProcessorMock.mockReset();
    loadProcessorMock.mockResolvedValue(mockProcessor);
    globalThis.FileReader =
      ControlledFileReader as unknown as typeof FileReader;
  });

  afterEach(() => {
    cleanup();
  });

  it("renders warning-only diagnostics without fatal section", async () => {
    captureMock.mockImplementation(() => ({
      packets: [],
      warnings: ["Truncated frame data"],
      errors: [],
    }));

    render(<App />);

    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: {
        files: [new File([Uint8Array.from([0x01])], "warn.pcap")],
      },
    });

    await waitFor(() => expect(activeReaders.length).toBeGreaterThan(0));
    await activeReaders[0]?.emitLoad();

    expect(
      await screen.findByText("⚠️ Non-fatal warnings"),
    ).toBeInTheDocument();
    expect(screen.getByText("Truncated frame data")).toBeInTheDocument();
    expect(screen.queryByText("⛔ Fatal parse errors")).not.toBeInTheDocument();
  });

  it("renders error-only diagnostics", async () => {
    captureMock.mockImplementation(() => ({
      packets: [],
      warnings: [],
      errors: ["Unsupported packet format"],
    }));

    render(<App />);

    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: {
        files: [new File([Uint8Array.from([0x02])], "error.pcap")],
      },
    });

    await waitFor(() => expect(activeReaders.length).toBeGreaterThan(0));
    await activeReaders[0]?.emitLoad();

    expect(
      await screen.findByText("⛔ Fatal parse errors"),
    ).toBeInTheDocument();
    expect(screen.getByText("Unsupported packet format")).toBeInTheDocument();
    expect(screen.queryByText("⚠️ Non-fatal warnings")).not.toBeInTheDocument();
  });

  it("renders both warnings and errors together", async () => {
    captureMock.mockImplementation(() => ({
      packets: [],
      warnings: ["Recovered packet boundary"],
      errors: ["CRC mismatch"],
    }));

    render(<App />);

    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: {
        files: [new File([Uint8Array.from([0x03])], "mixed.pcap")],
      },
    });

    await waitFor(() => expect(activeReaders.length).toBeGreaterThan(0));
    await activeReaders[0]?.emitLoad();

    expect(
      await screen.findByText("⛔ Fatal parse errors"),
    ).toBeInTheDocument();
    expect(screen.getByText("CRC mismatch")).toBeInTheDocument();
    expect(screen.getByText("⚠️ Non-fatal warnings")).toBeInTheDocument();
    expect(screen.getByText("Recovered packet boundary")).toBeInTheDocument();
  });
});
