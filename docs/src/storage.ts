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

function safeGet(key: string): string | null {
  const storage = getLocalStorage();
  if (!storage) {
    return null;
  }

  try {
    return storage.getItem(key);
  } catch (err) {
    console.warn(`Failed to read stored value for ${key}`, err);
    return null;
  }
}

function safeSet(key: string, value: string): boolean {
  const storage = getLocalStorage();
  if (!storage) {
    return false;
  }

  try {
    storage.setItem(key, value);
    return true;
  } catch (err) {
    return false;
  }
}

function safeRemove(key: string): boolean {
  const storage = getLocalStorage();
  if (!storage) {
    return false;
  }

  try {
    storage.removeItem(key);
    return true;
  } catch (err) {
    return false;
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
  let memoryList: string[] = [];

  function load(): string[] {
    const raw = safeGet(key);
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
      if (!safeRemove(key)) {
        console.warn("Failed to reset stored list after parse error", err);
      }
      return [];
    }
  }

  function remember(value: string): string[] {
    if (limit <= 0) {
      memoryList = [];
      if (!safeRemove(key)) {
        console.warn("Failed to clear stored list with non-positive limit");
      }
      return [];
    }

    const existing = load();
    const deduped = existing.filter((item) => item !== value);
    const updated = [value, ...deduped].slice(0, limit);

    memoryList = updated;
    if (!safeSet(key, JSON.stringify(updated))) {
      console.warn("Failed to persist stored list");
    }

    return [...updated];
  }

  function clear(): void {
    memoryList = [];
    if (!safeRemove(key)) {
      console.warn("Failed to clear stored list");
    }
  }

  return { load, remember, clear };
}

export function loadMaxFileSizeMB(): number | null {
  const value = safeGet(MAX_FILE_SIZE_KEY);
  if (value === null) {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function saveMaxFileSizeMB(value: number | null): boolean {
  if (value === null) {
    if (!safeRemove(MAX_FILE_SIZE_KEY)) {
      console.warn("Failed to persist max file size preference");
      return false;
    }

    return true;
  }

  if (!safeSet(MAX_FILE_SIZE_KEY, String(value))) {
    console.warn("Failed to persist max file size preference");
    return false;
  }

  return true;
}

export function loadFilterText(): string | null {
  return safeGet(FILTER_TEXT_KEY);
}

export function saveFilterText(value: string | null): boolean {
  if (value === null) {
    if (!safeRemove(FILTER_TEXT_KEY)) {
      console.warn("Failed to persist filter text preference");
      return false;
    }

    return true;
  }

  if (!safeSet(FILTER_TEXT_KEY, value)) {
    console.warn("Failed to persist filter text preference");
    return false;
  }

  return true;
}
