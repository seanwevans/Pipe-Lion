const MAX_FILE_SIZE_KEY = "pipe-lion:max-file-size-mb";
const FILTER_TEXT_KEY = "pipe-lion:filter-text";

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function getLocalStorage(): StorageLike | null {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    return window.localStorage;
  } catch (err) {
    console.warn("Unable to access localStorage", err);
    return null;
  }
}

export function loadMaxFileSizeMB(): number | null {
  const storage = getLocalStorage();
  if (!storage) {
    return null;
  }

  const value = storage.getItem(MAX_FILE_SIZE_KEY);
  if (value === null) {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function saveMaxFileSizeMB(value: number | null): void {
  const storage = getLocalStorage();
  if (!storage) {
    return;
  }

  if (value === null) {
    storage.removeItem(MAX_FILE_SIZE_KEY);
    return;
  }

  storage.setItem(MAX_FILE_SIZE_KEY, String(value));
}

export function loadFilterText(): string | null {
  const storage = getLocalStorage();
  if (!storage) {
    return null;
  }

  return storage.getItem(FILTER_TEXT_KEY);
}

export function saveFilterText(value: string | null): void {
  const storage = getLocalStorage();
  if (!storage) {
    return;
  }

  if (value === null) {
    storage.removeItem(FILTER_TEXT_KEY);
    return;
  }

  storage.setItem(FILTER_TEXT_KEY, value);
}
