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

const { processPacketMock, loadProcessorMock } = vi.hoisted(() => ({
  processPacketMock: vi.fn(),
  loadProcessorMock: vi.fn(),
}));

const mockProcessor = {
  process_packet: (data: Uint8Array) => processPacketMock(data),
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

describe("App restart flow", () => {
  beforeEach(() => {
    activeReaders.length = 0;
    processPacketMock.mockReset();
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

    processPacketMock.mockImplementation(() => ({
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
    const restartButton = restartButtons.find(
      (button) => !button.hasAttribute("disabled"),
    );
    expect(restartButton).toBeDefined();
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

    await waitFor(() => expect(processPacketMock).toHaveBeenCalledTimes(1));

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

  it("prevents stale packets from reappearing after restart", async () => {
    const user = userEvent.setup();

    processPacketMock.mockImplementation(() => ({
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
    const restartButton = restartButtons.find(
      (button) => !button.hasAttribute("disabled"),
    );
    expect(restartButton).toBeDefined();
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
    expect(processPacketMock).not.toHaveBeenCalled();

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
    expect(processPacketMock).not.toHaveBeenCalled();

    await Promise.all(activeReaders.map((reader) => reader.emitLoad()));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(processPacketMock).not.toHaveBeenCalled();
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
    processPacketMock.mockReset();
    loadProcessorMock.mockReset();
    loadProcessorMock.mockResolvedValue(mockProcessor);
    globalThis.FileReader =
      ControlledFileReader as unknown as typeof FileReader;
  });

  afterEach(() => {
    cleanup();
  });

  it("renders warning-only diagnostics without fatal section", async () => {
    processPacketMock.mockImplementation(() => ({
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
    processPacketMock.mockImplementation(() => ({
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
    processPacketMock.mockImplementation(() => ({
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
