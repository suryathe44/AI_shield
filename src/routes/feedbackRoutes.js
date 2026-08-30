import { sanitizeContent } from "../../shared/textUtils.js";
import { readJsonBody, sendJson } from "../utils/http.js";

export const FEEDBACK_CATEGORIES = [
  "Useful",
  "Confusing",
  "False Positive",
  "False Negative",
  "Feature Request",
  "Other",
];

export async function handleFeedbackRoutes(req, res, url, context) {
  if (req.method !== "POST" || url.pathname !== "/api/feedback") {
    return false;
  }

  const body = await readJsonBody(req, context.config.maxBodyBytes);
  if (!Number.isInteger(body.rating) || body.rating < 1 || body.rating > 5) {
    sendJson(res, 400, { error: "Rating must be an integer from 1 to 5." });
    return true;
  }

  if (!FEEDBACK_CATEGORIES.includes(body.category)) {
    sendJson(res, 400, { error: "Select a valid feedback category." });
    return true;
  }

  if (body.comment !== undefined && typeof body.comment !== "string") {
    sendJson(res, 400, { error: "Comment must be text." });
    return true;
  }

  const rawComment = body.comment ?? "";
  if (rawComment.length > 500) {
    sendJson(res, 400, { error: "Comment must be 500 characters or fewer." });
    return true;
  }

  const { content: comment } = sanitizeContent(rawComment, 500);
  const record = await context.feedbackStore.append({
    rating: body.rating,
    category: body.category,
    comment,
  });

  sendJson(res, 201, {
    success: true,
    feedbackId: record.id,
  });
  return true;
}
