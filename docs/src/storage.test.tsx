import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createStoredList,
  saveFilterText,
  saveMaxFileSizeMB,
} from "./storage";

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe("storage persistence", () => {
  it("returns false when localStorage is unavailable", () => {
    vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
      throw new Error("denied");
    });

    expect(saveMaxFileSizeMB(25)).toBe(false);
    expect(saveFilterText("tcp")).toBe(false);
  });

  it("returns false when max file size write fails", () => {
    const setItemMock = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new DOMException("quota", "QuotaExceededError");
      });

    expect(saveMaxFileSizeMB(42)).toBe(false);
    expect(setItemMock).toHaveBeenCalled();
  });

  it("returns false when filter text removal fails", () => {
    const removeItemMock = vi
      .spyOn(Storage.prototype, "removeItem")
      .mockImplementation(() => {
        throw new Error("remove failed");
      });

    expect(saveFilterText(null)).toBe(false);
    expect(removeItemMock).toHaveBeenCalled();
  });
});

describe("createStoredList parse reset", () => {
  it("clears malformed stored lists and returns empty values", () => {
    window.localStorage.setItem("recent-captures", "{bad json");
    const removeItemSpy = vi.spyOn(Storage.prototype, "removeItem");

    const storedList = createStoredList("recent-captures", 5);

    expect(storedList.load()).toEqual([]);
    expect(removeItemSpy).toHaveBeenCalledWith("recent-captures");
    expect(window.localStorage.getItem("recent-captures")).toBeNull();
  });
});
