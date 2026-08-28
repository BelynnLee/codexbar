// In-place DOM morphing (node-diffing). Replaces wholesale `innerHTML = html` swaps so that a
// background refresh patches only the nodes that actually changed — preserving scroll position,
// input focus/selection, `<details>` open state, and (crucially) the live SVG chart nodes, which
// no longer flash on every refresh.
//
// The reconciliation walks the two trees in parallel and reuses a node whenever its type, tag, and
// `data-key` match; otherwise it replaces. New nodes are *imported* from the parsed source into the
// target document (`importNode`), so SVG stays in the SVG namespace without any manual namespacing
// here — the browser's `<template>` parser already put the source nodes in the right namespace.
//
// The core `morph()` operates purely on the small DOM interface below, so the diff algorithm is
// unit-tested against plain fake nodes (see tests/dom.test.mjs); only `morphHtml()` touches a real
// document, and that part is a one-line `<template>` parse.

export interface NodeLike {
  nodeType: number;
  nodeName: string;
  nodeValue: string | null;
  childNodes: ArrayLike<NodeLike>;
  ownerDocument?: { importNode(node: NodeLike, deep: boolean): NodeLike } | null;
  firstChild?: NodeLike | null;
  // Element-only members (guarded by nodeType === 1 before use).
  getAttribute?(name: string): string | null;
  setAttribute?(name: string, value: string): void;
  removeAttribute?(name: string): void;
  hasAttribute?(name: string): boolean;
  getAttributeNames?(): string[];
  // Parent mutations.
  appendChild(node: NodeLike): NodeLike;
  removeChild(node: NodeLike): NodeLike;
  replaceChild(next: NodeLike, previous: NodeLike): NodeLike;
  // Live form-control properties (duck-typed; present only on real inputs/selects).
  value?: string;
  checked?: boolean;
}

const ELEMENT = 1;
const TEXT = 3;
const COMMENT = 8;

export interface MorphOptions {
  /// Returns true if the node is the user's current focus/edit target, so its live value/selection
  /// is never clobbered by a refresh. Defaults to `document.activeElement` when a document exists.
  isFocused?: (node: NodeLike) => boolean;
}

function defaultIsFocused(node: NodeLike): boolean {
  const doc = (globalThis as { document?: { activeElement?: unknown } }).document;
  return !!doc && doc.activeElement === (node as unknown);
}

function key(node: NodeLike): string | null {
  return node.nodeType === ELEMENT && node.getAttribute ? node.getAttribute("data-key") : null;
}

function sameNode(a: NodeLike, b: NodeLike): boolean {
  return a.nodeType === b.nodeType && a.nodeName === b.nodeName && key(a) === key(b);
}

function adopt(parent: NodeLike, source: NodeLike): NodeLike {
  const doc = parent.ownerDocument;
  return doc ? doc.importNode(source, true) : source;
}

function syncAttributes(from: NodeLike, to: NodeLike): void {
  if (!from.getAttributeNames || !to.getAttributeNames) return;
  for (const name of from.getAttributeNames()) {
    if (!to.hasAttribute?.(name)) from.removeAttribute?.(name);
  }
  for (const name of to.getAttributeNames()) {
    const next = to.getAttribute?.(name) ?? "";
    if (from.getAttribute?.(name) !== next) from.setAttribute?.(name, next);
  }
}

function syncLiveProps(from: NodeLike, to: NodeLike, isFocused: (node: NodeLike) => boolean): void {
  const tag = from.nodeName;
  if (tag !== "INPUT" && tag !== "TEXTAREA") return;
  if (isFocused(from)) return; // don't overwrite an edit in progress
  if ("value" in from && to.getAttribute) {
    const attr = to.getAttribute("value");
    if (attr !== null && from.value !== attr) from.value = attr;
  }
  if (tag === "INPUT" && "checked" in from) {
    const checked = to.hasAttribute?.("checked") ?? false;
    if (from.checked !== checked) from.checked = checked;
  }
}

function morphNode(from: NodeLike, to: NodeLike, isFocused: (node: NodeLike) => boolean): void {
  if (from.nodeType === TEXT || from.nodeType === COMMENT) {
    if (from.nodeValue !== to.nodeValue) from.nodeValue = to.nodeValue;
    return;
  }
  if (from.nodeType === ELEMENT) {
    syncAttributes(from, to);
    syncLiveProps(from, to, isFocused);
    morphChildren(from, to, isFocused);
  }
}

function morphChildren(from: NodeLike, to: NodeLike, isFocused: (node: NodeLike) => boolean): void {
  const fromChildren = Array.from(from.childNodes);
  const toChildren = Array.from(to.childNodes);
  const len = Math.max(fromChildren.length, toChildren.length);
  for (let i = 0; i < len; i += 1) {
    const f = fromChildren[i];
    const t = toChildren[i];
    if (t === undefined) {
      from.removeChild(f);
    } else if (f === undefined) {
      from.appendChild(adopt(from, t));
    } else if (sameNode(f, t)) {
      morphNode(f, t, isFocused);
    } else {
      from.replaceChild(adopt(from, t), f);
    }
  }
}

/// Reconcile `target`'s children to match `source`'s children, mutating `target` in place.
/// `target` and `source` are typically both container nodes (e.g. a `.content` element and a parsed
/// `<template>` content fragment).
export function morph(target: NodeLike, source: NodeLike, options: MorphOptions = {}): void {
  const isFocused = options.isFocused ?? defaultIsFocused;
  morphChildren(target, source, isFocused);
}

/// Browser entrypoint: parse `html` (via `<template>`, which correctly namespaces SVG/HTML) and
/// morph it into `target`. This is the drop-in replacement for `target.innerHTML = html`.
export function morphHtml(target: Element, html: string, options: MorphOptions = {}): void {
  const template = target.ownerDocument.createElement("template");
  template.innerHTML = html;
  morph(target as unknown as NodeLike, template.content as unknown as NodeLike, options);
}
