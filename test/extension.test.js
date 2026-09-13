import test from "node:test";
import assert from "node:assert/strict";
import { captureText } from "../extension/capture.js";
import { readFile } from "node:fs/promises";

test("extension captures only selected text and caps page content", () => {
  globalThis.window = { getSelection: () => "selected message" };
  globalThis.location = { href: "https://example.com/" };
  globalThis.document = { body: { innerText: "x".repeat(21000) } };
  try {
    assert.deepEqual(captureText("selection"), { text: "selected message", truncated: false });
    const page = captureText("page");
    assert.equal(page.text.length, 20000);
    assert.equal(page.truncated, true);
    assert.ok(page.text.startsWith("https://example.com/\n"));
    window.getSelection = () => "";
    assert.equal(captureText("selection").text, "");
  } finally {
    delete globalThis.window; delete globalThis.location; delete globalThis.document;
  }
});
test("extension limits access to user-invoked scans and blocks network connections", async () => {
  const manifest = JSON.parse(await readFile(new URL("../extension/manifest.json", import.meta.url)));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ["activeTab", "scripting"]);
  assert.equal(manifest.host_permissions, undefined);
  assert.match(manifest.content_security_policy.extension_pages, /connect-src 'none'/);
});
