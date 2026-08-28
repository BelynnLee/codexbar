import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../src/store.ts", import.meta.url), "utf8");
const javascript = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const { createStore } = await import(`data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`);

// A manual scheduler so flushes are deterministic in tests.
function manual() {
  const queue = [];
  return { schedule: (flush) => queue.push(flush), run: () => queue.splice(0).forEach((f) => f()) };
}

test("batches multiple mutations in a tick into a single notification", () => {
  const sched = manual();
  const store = createStore({ a: 1, b: 1 }, sched.schedule);
  let notifications = 0;
  store.subscribe(() => (notifications += 1));
  store.set({ a: 2 });
  store.set({ b: 3 });
  store.update((s) => ({ a: s.a + 10 }));
  assert.equal(notifications, 0, "no synchronous notification before flush");
  sched.run();
  assert.equal(notifications, 1, "coalesced into one notification");
  assert.deepEqual(store.get(), { a: 12, b: 3 });
});

test("no-op patches schedule no notification", () => {
  const sched = manual();
  const store = createStore({ a: 1 }, sched.schedule);
  let notifications = 0;
  store.subscribe(() => (notifications += 1));
  store.set({ a: 1 }); // Object.is-equal
  sched.run();
  assert.equal(notifications, 0);
});

test("flush() runs a pending batch synchronously", () => {
  const store = createStore({ a: 1 }, () => {}); // scheduler never runs on its own
  let notifications = 0;
  store.subscribe(() => (notifications += 1));
  store.set({ a: 2 });
  store.flush();
  assert.equal(notifications, 1);
  store.flush(); // nothing pending
  assert.equal(notifications, 1);
});

test("unsubscribe stops future notifications", () => {
  const sched = manual();
  const store = createStore({ a: 1 }, sched.schedule);
  let count = 0;
  const off = store.subscribe(() => (count += 1));
  store.set({ a: 2 });
  sched.run();
  off();
  store.set({ a: 3 });
  sched.run();
  assert.equal(count, 1);
});

test("state snapshots are replaced, not mutated in place", () => {
  const store = createStore({ a: 1 }, () => {});
  const before = store.get();
  store.set({ a: 2 });
  assert.equal(before.a, 1, "old snapshot is untouched");
  assert.notEqual(store.get(), before, "new snapshot is a fresh object");
});
