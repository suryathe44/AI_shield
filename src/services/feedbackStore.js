import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export function createFeedbackId() {
  return `FB-${randomBytes(6).toString("hex").toUpperCase()}`;
}

export function calculateFeedbackMetrics(records) {
  const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  const categoryCounts = {};
  let ratingTotal = 0;

  for (const record of records) {
    ratingCounts[record.rating] += 1;
    categoryCounts[record.category] = (categoryCounts[record.category] ?? 0) + 1;
    ratingTotal += record.rating;
  }

  return {
    totalFeedback: records.length,
    averageRating: records.length ? Number((ratingTotal / records.length).toFixed(2)) : 0,
    ratingCounts,
    categoryCounts,
    falsePositiveReports: categoryCounts["False Positive"] ?? 0,
    falseNegativeReports: categoryCounts["False Negative"] ?? 0,
  };
}

export class FeedbackStore {
  constructor({ filePath }) {
    this.filePath = filePath;
    this.queue = Promise.resolve();
  }

  async readRecords() {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      if (error.code === "ENOENT") {
        return [];
      }

      throw error;
    }
  }

  async writeRecords(records) {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const temporaryPath = `${this.filePath}.${process.pid}.tmp`;
    await writeFile(temporaryPath, JSON.stringify(records, null, 2), "utf8");
    await rename(temporaryPath, this.filePath);
  }

  async withLock(task) {
    const nextTask = this.queue.then(task, task);
    this.queue = nextTask.catch(() => {});
    return nextTask;
  }

  async append({ rating, category, comment }) {
    return this.withLock(async () => {
      const records = await this.readRecords();
      const record = {
        id: createFeedbackId(),
        rating,
        category,
        comment,
        createdAt: new Date().toISOString(),
      };

      records.unshift(record);
      await this.writeRecords(records);
      return record;
    });
  }

  async getAdminView() {
    return this.withLock(async () => {
      const feedback = await this.readRecords();
      return {
        feedback,
        metrics: calculateFeedbackMetrics(feedback),
        storage: {
          durableOnRender: false,
          type: "local-file",
        },
      };
    });
  }
}
