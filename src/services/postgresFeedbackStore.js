import pg from "pg";
import { calculateFeedbackMetrics, createFeedbackId } from "./feedbackStore.js";

const { Pool } = pg;

export class PostgresFeedbackStore {
  constructor({ connectionString, ssl = false, pool } = {}) {
    const poolConfig = { connectionString };
    if (ssl) {
      poolConfig.ssl = { rejectUnauthorized: false };
    }
    this.pool = pool ?? new Pool(poolConfig);
    this.ready = null;
  }

  ensureReady() {
    if (!this.ready) {
      this.ready = this.pool.query(`
        CREATE TABLE IF NOT EXISTS ai_shield_feedback (
          id VARCHAR(15) PRIMARY KEY,
          rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
          category VARCHAR(32) NOT NULL,
          comment VARCHAR(500) NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `).catch((error) => {
        this.ready = null;
        throw error;
      });
    }

    return this.ready;
  }

  async append({ rating, category, comment }) {
    await this.ensureReady();
    const id = createFeedbackId();
    const result = await this.pool.query(
      `INSERT INTO ai_shield_feedback (id, rating, category, comment)
       VALUES ($1, $2, $3, $4)
       RETURNING id, rating, category, comment, created_at AS "createdAt"`,
      [id, rating, category, comment],
    );
    return result.rows[0];
  }

  async getAdminView() {
    await this.ensureReady();
    const result = await this.pool.query(
      `SELECT id, rating, category, comment, created_at AS "createdAt"
       FROM ai_shield_feedback
       ORDER BY created_at DESC`,
    );
    const feedback = result.rows.map((record) => ({
      ...record,
      rating: Number(record.rating),
      createdAt: new Date(record.createdAt).toISOString(),
    }));

    return {
      feedback,
      metrics: calculateFeedbackMetrics(feedback),
      storage: {
        durableOnRender: true,
        type: "postgresql",
      },
    };
  }

  async close() {
    await this.pool.end();
  }
}
