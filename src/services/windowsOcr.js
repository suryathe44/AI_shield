import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

function makeError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

export class WindowsOcrService {
  constructor({
    scriptPath = path.resolve(process.cwd(), "scripts/windows-ocr.ps1"),
    timeoutMs = 45_000,
  } = {}) {
    this.scriptPath = scriptPath;
    this.timeoutMs = timeoutMs;
  }

  async extractTextFromDataUrl(dataUrl) {
    const match = /^data:(image\/(?:png|jpeg|jpg));base64,(.+)$/i.exec(String(dataUrl ?? ""));
    if (!match) {
      throw makeError("A PNG or JPEG screen capture is required.", 400);
    }

    const extension = match[1].includes("png") ? ".png" : ".jpg";
    const imageBuffer = Buffer.from(match[2], "base64");
    if (!imageBuffer.length) {
      throw makeError("The provided screen capture was empty.", 400);
    }

    return this.extractTextFromBuffer(imageBuffer, extension);
  }

  async extractTextFromBuffer(imageBuffer, extension = ".png") {
    const tempDirectory = await mkdtemp(path.join(os.tmpdir(), "ai-shield-ocr-"));
    const imagePath = path.join(tempDirectory, `screen-capture${extension}`);

    try {
      await writeFile(imagePath, imageBuffer);
      const text = await this.runWindowsOcr(imagePath);
      const normalizedText = String(text ?? "").replace(/\r/g, "").trim();

      return {
        engine: "windows-media-ocr",
        lineCount: normalizedText ? normalizedText.split(/\n+/).filter(Boolean).length : 0,
        text: normalizedText,
      };
    } finally {
      await rm(tempDirectory, { recursive: true, force: true }).catch(() => {});
    }
  }

  async runWindowsOcr(imagePath) {
    return new Promise((resolve, reject) => {
      const child = spawn(
        "powershell.exe",
        [
          "-NoProfile",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          this.scriptPath,
          "-ImagePath",
          imagePath,
        ],
        {
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        },
      );

      let stdout = "";
      let stderr = "";
      const timeout = setTimeout(() => {
        child.kill();
        reject(makeError("Windows OCR timed out while analyzing the screen capture.", 504));
      }, this.timeoutMs);

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString("utf8");
      });

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString("utf8");
      });

      child.on("error", (error) => {
        clearTimeout(timeout);
        reject(makeError(`Windows OCR could not start: ${error.message}`, 500));
      });

      child.on("close", (code) => {
        clearTimeout(timeout);

        if (code !== 0) {
          reject(
            makeError(
              stderr.trim() || "Windows OCR failed while processing the screen capture.",
              500,
            ),
          );
          return;
        }

        resolve(stdout);
      });
    });
  }
}
