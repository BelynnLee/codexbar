import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../src/dom.ts", import.meta.url), "utf8");
const javascript = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const { morph } = await import(`data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`);

// A minimal faithful DOM model exercising exactly the interface morph() uses. importNode deep-clones
// with a fresh identity so tests can assert node reuse vs. replacement.
const doc = {
  importNode(node, deep) {
    return node.clone(deep);
  },
};

class FakeNode {
  constructor(nodeType, nodeName, nodeValue = null) {
    this.nodeType = nodeType;
    this.nodeName = nodeName;
    this.nodeValue = nodeValue;
    this.childNodes = [];
    this.attrs = new Map();
    this.ownerDocument = doc;
    this.value = undefined;
    this.checked = undefined;
  }
  getAttribute(name) {
    return this.attrs.has(name) ? this.attrs.get(name) : null;
  }
  setAttribute(name, value) {
    this.attrs.set(name, String(value));
  }
  removeAttribute(name) {
    this.attrs.delete(name);
  }
  hasAttribute(name) {
    return this.attrs.has(name);
  }
  getAttributeNames() {
    return [...this.attrs.keys()];
  }
  appendChild(node) {
    this.childNodes.push(node);
    return node;
  }
  removeChild(node) {
    this.childNodes = this.childNodes.filter((c) => c !== node);
    return node;
  }
  replaceChild(next, previous) {
    this.childNodes = this.childNodes.map((c) => (c === previous ? next : c));
    return previous;
  }
  clone(deep) {
    const copy = new FakeNode(this.nodeType, this.nodeName, this.nodeValue);
    copy.attrs = new Map(this.attrs);
    copy.value = this.value;
    copy.checked = this.checked;
    if (deep) copy.childNodes = this.childNodes.map((c) => c.clone(true));
    return copy;
  }
}

function el(name, attrs = {}, children = []) {
  const node = new FakeNode(1, name.toUpperCase());
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  node.childNodes = children;
  return node;
}
const text = (value) => new FakeNode(3, "#text", value);
const root = (children) => el("DIV", {}, children);

test("updates text without replacing the node", () => {
  const from = root([text("old")]);
  const original = from.childNodes[0];
  morph(from, root([text("new")]));
  assert.equal(from.childNodes[0], original, "text node reused");
  assert.equal(from.childNodes[0].nodeValue, "new");
});

test("syncs attributes: add, update, remove", () => {
  const from = root([el("span", { class: "a", title: "keep" })]);
  const target = from.childNodes[0];
  morph(from, root([el("span", { class: "b", role: "note" })]));
  assert.equal(from.childNodes[0], target, "element reused");
  assert.equal(target.getAttribute("class"), "b", "updated");
  assert.equal(target.getAttribute("role"), "note", "added");
  assert.equal(target.getAttribute("title"), null, "removed");
});

test("appends and removes children to match source length", () => {
  const from = root([el("i")]);
  morph(from, root([el("i"), el("b"), el("u")]));
  assert.deepEqual(from.childNodes.map((c) => c.nodeName), ["I", "B", "U"]);
  morph(from, root([el("i")]));
  assert.deepEqual(from.childNodes.map((c) => c.nodeName), ["I"]);
});

test("replaces when tag differs", () => {
  const from = root([el("div")]);
  const original = from.childNodes[0];
  morph(from, root([el("span")]));
  assert.notEqual(from.childNodes[0], original, "replaced with fresh node");
  assert.equal(from.childNodes[0].nodeName, "SPAN");
});

test("reuses on matching data-key, replaces on differing key", () => {
  const from = root([el("li", { "data-key": "x" })]);
  const kept = from.childNodes[0];
  morph(from, root([el("li", { "data-key": "x", class: "hot" })]));
  assert.equal(from.childNodes[0], kept, "same key reused");
  assert.equal(kept.getAttribute("class"), "hot");

  morph(from, root([el("li", { "data-key": "y" })]));
  assert.notEqual(from.childNodes[0], kept, "different key replaced");
});

test("morphs nested children in place", () => {
  const inner = el("span", {}, [text("1")]);
  const from = root([el("p", {}, [inner])]);
  morph(from, root([el("p", {}, [el("span", {}, [text("2")])])]));
  assert.equal(from.childNodes[0].childNodes[0], inner, "nested element reused");
  assert.equal(inner.childNodes[0].nodeValue, "2");
});

test("does not clobber the live value of the focused input", () => {
  const input = el("input", { value: "server" });
  input.value = "user typing";
  const from = root([input]);
  morph(from, root([el("input", { value: "server" })]), { isFocused: (n) => n === input });
  assert.equal(input.value, "user typing", "focused edit preserved");

  morph(from, root([el("input", { value: "server" })]), { isFocused: () => false });
  assert.equal(input.value, "server", "unfocused input reflects source value");
});
