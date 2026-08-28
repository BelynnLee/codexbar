// A minimal reactive store. State lives in one place; subscribers are notified on change, and
// notifications are *batched* onto a microtask so several mutations in the same tick (e.g. the
// `usage-updated` and `warnings-updated` events that arrive back-to-back) collapse into a single
// render pass instead of one render each. Pure logic with no DOM or Tauri dependency, so it is
// unit-tested in isolation (see tests/store.test.mjs).

export type Listener = () => void;
export type Updater<T> = (previous: T) => Partial<T>;

export interface Store<T> {
  /// The current state snapshot. Treat it as immutable — mutate through `set`/`update`.
  get(): T;
  /// Shallow-merge a patch. If every key in the patch is already `Object.is`-equal to the current
  /// value, this is a no-op and no notification is scheduled.
  set(patch: Partial<T>): void;
  /// Like `set`, but the patch is computed from the current state.
  update(updater: Updater<T>): void;
  /// Register a listener. Returns an unsubscribe function. Listeners fire once per batched flush,
  /// after all mutations in the tick have applied.
  subscribe(listener: Listener): () => void;
  /// Run any pending batched notification immediately instead of waiting for the microtask. Useful
  /// in tests and when a synchronous render is required before yielding to the event loop.
  flush(): void;
}

/// A batching scheduler. Defaults to `queueMicrotask`; tests inject a manual scheduler so flushes
/// are deterministic. The scheduler is asked to run `flush` at most once per pending batch.
export type Scheduler = (flush: () => void) => void;

const microtaskScheduler: Scheduler = (flush) => queueMicrotask(flush);

export function createStore<T extends object>(initial: T, scheduler: Scheduler = microtaskScheduler): Store<T> {
  let state = initial;
  const listeners = new Set<Listener>();
  let pending = false;

  const flush = (): void => {
    if (!pending) return;
    pending = false;
    // Snapshot listeners so unsubscribing mid-flush doesn't skip a sibling listener.
    for (const listener of [...listeners]) listener();
  };

  const schedule = (): void => {
    if (pending) return;
    pending = true;
    scheduler(flush);
  };

  const applyPatch = (patch: Partial<T>): void => {
    let changed = false;
    for (const key of Object.keys(patch) as (keyof T)[]) {
      const next = patch[key] as T[keyof T];
      if (!Object.is(state[key], next)) {
        if (!changed) {
          state = { ...state };
          changed = true;
        }
        state[key] = next;
      }
    }
    if (changed) schedule();
  };

  return {
    get: () => state,
    set: (patch) => applyPatch(patch),
    update: (updater) => applyPatch(updater(state)),
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    flush,
  };
}
