import { analyzeContent } from "./shared/detectionEngine.js";
import { captureText } from "./capture.js";
const $ = (id) => document.getElementById(id);
const buttons = [...document.querySelectorAll("button")];
function list(id, values) {
  $(id).replaceChildren(...values.map((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    return li;
  }));
}
function analyze(text, source, truncated = false) {
  if (!text.trim()) throw new Error(source === "selection" ? "Select text on the page first, then try again." : "Add some text to analyze first.");
  const result = analyzeContent({ content: text, source });
  $("result").dataset.level = result.classification;
  $("verdict").textContent = result.classification;
  $("score").textContent = result.riskScore;
  $("meter").value = result.riskScore;
  $("summary").textContent = result.summary;
  list("reasons", result.explanation.length ? result.explanation : ["No major scam signals detected in the analyzed text."]);
  list("advice", result.recommendations);
  $("result").hidden = false;
  $("status").textContent = `Analyzed ${text.length.toLocaleString()} characters locally.${truncated ? " Content was limited to the first 20,000 characters." : ""}`;
}
async function run(action) {
  buttons.forEach((button) => { button.disabled = true; });
  $("result").hidden = true;
  $("status").textContent = "Analyzing locally…";
  try { await action(); }
  catch (error) { $("status").textContent = error.message || "Unable to scan this content."; }
  finally { buttons.forEach((button) => { button.disabled = false; }); }
}
async function scan(mode) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !/^https?:\/\//i.test(tab.url || "")) {
    throw new Error("Open a regular HTTP or HTTPS webpage to scan. You can also paste text here.");
  }
  let captures;
  try {
    captures = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: captureText, args: [mode] });
  } catch {
    throw new Error("Chrome does not allow scanning this page. Paste the text here instead.");
  }
  const captured = captures?.[0]?.result;
  if (!captured || typeof captured.text !== "string") throw new Error("Could not read page text. Please try again.");
  analyze(captured.text, mode, captured.truncated);
}
$("analyze").addEventListener("click", () => run(() => analyze($("message").value, "message")));
$("selection").addEventListener("click", () => run(() => scan("selection")));
$("page").addEventListener("click", () => run(() => scan("page")));
$("message").addEventListener("input", () => { $("result").hidden = true; $("status").textContent = ""; });
$("clear").addEventListener("click", () => { $("message").value = ""; $("result").hidden = true; $("status").textContent = ""; $("message").focus(); });
