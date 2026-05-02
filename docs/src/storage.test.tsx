import { describe, expect, it, vi } from "vitest";
import { createStoredList, saveFilterText, saveMaxFileSizeMB } from "./storage";

describe("storage persistence", () => {
  it("returns false when storage is unavailable", () => {
    const localStorageDescriptor = Object.getOwnPropertyDescriptor(
      window,
      "localStorage",
    );
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() {
        throw new Error("blocked");
      },
    });

    expect(saveMaxFileSizeMB(25)).toBe(false);
    expect(saveFilterText("tcp")).toBe(false);

    if (localStorageDescriptor) {
      Object.defineProperty(window, "localStorage", localStorageDescriptor);
    }
  });

  it("returns false when writes fail with quota errors", () => {
    const setSpy = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new DOMException("quota", "QuotaExceededError");
      });

    expect(saveMaxFileSizeMB(25)).toBe(false);
    expect(saveFilterText("udp")).toBe(false);

    setSpy.mockRestore();
  });

  it("resets invalid stored list values after parse failures", () => {
    const key = "pipe-lion:test-parse-reset";
    window.localStorage.setItem(key, "{not-json");
    const removeSpy = vi.spyOn(Storage.prototype, "removeItem");

    const list = createStoredList(key, 3);
    expect(list.load()).toEqual([]);
    expect(removeSpy).toHaveBeenCalledWith(key);

    removeSpy.mockRestore();
  });
});
