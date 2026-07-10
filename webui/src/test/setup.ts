import "@testing-library/jest-dom/vitest";

// jsdom has no EventSource. This stub lets components that use the realtime
// stream hook render in tests, and lets a test drive events via emit().
type Listener = (e: MessageEvent) => void;

export class MockEventSource {
  static instances: MockEventSource[] = [];
  static reset() {
    MockEventSource.instances = [];
  }

  url: string;
  withCredentials: boolean;
  listeners: Record<string, Listener[]> = {};

  constructor(url: string, init?: { withCredentials?: boolean }) {
    this.url = url;
    this.withCredentials = init?.withCredentials ?? false;
    MockEventSource.instances.push(this);
  }

  addEventListener(type: string, cb: Listener) {
    (this.listeners[type] ??= []).push(cb);
  }
  removeEventListener(type: string, cb: Listener) {
    this.listeners[type] = (this.listeners[type] ?? []).filter((l) => l !== cb);
  }
  close() {}

  // Test helper: dispatch a named event carrying JSON data.
  emit(type: string, data: unknown) {
    for (const cb of this.listeners[type] ?? []) {
      cb({ data: JSON.stringify(data) } as MessageEvent);
    }
  }
}

(globalThis as unknown as { EventSource: unknown }).EventSource = MockEventSource;
