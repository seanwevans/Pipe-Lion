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

type StoredList = {
  load: () => string[];
  remember: (value: string) => string[];
  clear: () => void;
};

function sanitizeValues(values: unknown, limit: number): string[] {
  if (!Array.isArray(values) || limit <= 0) {
    return [];
  }

  const result: string[] = [];
  for (const value of values) {
    if (typeof value === "string") {
      result.push(value);
    }

    if (result.length >= limit) {
      break;
    }
  }

  return result;
}

export function createStoredList(key: string, limit: number): StoredList {
  const storage = getLocalStorage();
  let memoryList: string[] = [];

  function load(): string[] {
    if (!storage) {
      return [...memoryList.slice(0, Math.max(0, limit))];
    }

    const raw = storage.getItem(key);
    if (raw === null) {
      memoryList = [];
      return [];
    }

    try {
      const parsed = JSON.parse(raw);
      const sanitized = sanitizeValues(parsed, limit);
      memoryList = sanitized;
      return [...sanitized];
    } catch (err) {
      console.warn("Failed to parse stored list", err);
      memoryList = [];
      try {
        storage.removeItem(key);
      } catch (removeErr) {
        console.warn("Failed to reset stored list after parse error", removeErr);
      }
      return [];
    }
  }

  function remember(value: string): string[] {
    if (limit <= 0) {
      memoryList = [];
      if (storage) {
        try {
          storage.removeItem(key);
        } catch (err) {
          console.warn("Failed to clear stored list with non-positive limit", err);
        }
      }
      return [];
    }

    const existing = load();
    const deduped = existing.filter((item) => item !== value);
    const updated = [value, ...deduped].slice(0, limit);

    memoryList = updated;
    if (storage) {
      try {
        storage.setItem(key, JSON.stringify(updated));
      } catch (err) {
        console.warn("Failed to persist stored list", err);
      }
    }

    return [...updated];
  }

  function clear(): void {
    memoryList = [];
    if (storage) {
      try {
        storage.removeItem(key);
      } catch (err) {
        console.warn("Failed to clear stored list", err);
      }
    }
  }

  return { load, remember, clear };
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
