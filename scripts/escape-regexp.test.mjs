import assert from "node:assert/strict";
import test from "node:test";
import { escapeRegExp } from "./escape-regexp.mjs";

test("escapeRegExp es canonico en Node 22", () => {
  assert.equal(escapeRegExp("0.7.0-lab.21"), "0\\.7\\.0-lab\\.21");
  assert.equal(escapeRegExp("a+b(c)"), "a\\+b\\(c\\)");
  assert.equal(escapeRegExp("foo$bar^baz"), "foo\\$bar\\^baz");
  assert.ok(new RegExp(escapeRegExp("0.7.0-lab.21"), "u").test("0.7.0-lab.21"));
  assert.ok(!new RegExp(escapeRegExp("0.7.0-lab.21"), "u").test("0x7x0-labx21"));
});
