// Serialized by chrome.scripting; keep this function self-contained.
export function captureText(mode) {
  const limit = 20000;
  const text = mode === "selection"
    ? String(window.getSelection() || "")
    : `${location.href}\n${document.body?.innerText || ""}`;
  return { text: text.slice(0, limit), truncated: text.length > limit };
}
