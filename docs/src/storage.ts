const memoryStore = new Map<string, string>();

type StorageLike = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
};

function getBrowserStorage(): StorageLike {
  if (typeof window !== "undefined" && window.localStorage) {
    try {
      const testKey = "pipe-lion-storage-test";
      window.localStorage.setItem(testKey, "1");
      window.localStorage.removeItem(testKey);
      return window.localStorage;
    } catch (err) {
      console.debug("Falling back to in-memory storage", err);
    }
  }

  return {
    getItem: (key) => memoryStore.get(key) ?? null,
    setItem: (key, value) => {
      memoryStore.set(key, value);
    },
    removeItem: (key) => {
      memoryStore.delete(key);
    },
  };
}

function normaliseList(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return [];
  }

  return input
    .map((value) => (typeof value === "string" ? value : null))
    .filter((value): value is string => value !== null);
}

export function createStoredList(key: string, limit = 5) {
  function load(): string[] {
    const storage = getBrowserStorage();
    const raw = storage.getItem(key);
    if (!raw) {
      return [];
    }

    try {
      const parsed = JSON.parse(raw);
      return normaliseList(parsed).slice(0, limit);
    } catch (err) {
      console.debug("Failed to parse stored list", err);
      return [];
    }
  }

  function save(values: string[]) {
    const storage = getBrowserStorage();
    if (values.length === 0) {
      storage.removeItem(key);
      return;
    }

    storage.setItem(key, JSON.stringify(values.slice(0, limit)));
  }

  function remember(value: string): string[] {
    const trimmed = value.trim();
    if (!trimmed) {
      return load();
    }

    const existing = load();
    const deduped = existing.filter((entry) => entry !== trimmed);
    deduped.unshift(trimmed);
    const result = deduped.slice(0, limit);
    save(result);
    return result;
  }

  function clear() {
    const storage = getBrowserStorage();
    storage.removeItem(key);
  }

  return { load, save, remember, clear };
}

export type StoredList = ReturnType<typeof createStoredList>;
