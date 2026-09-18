#!/usr/bin/env python3
"""Compute v2 metrics/CIs and render publication figures using stdlib + matplotlib."""

import json
import math
from pathlib import Path
import random
from statistics import median
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "research" / "v2"
raw = json.loads((OUT / "predictions_v2.json").read_text())
manifest = json.loads((OUT / "evaluation_manifest.json").read_text())


def metric(rows):
    tp = sum(r["actual"] == "scam" and r["predicted"] == "scam" for r in rows)
    tn = sum(r["actual"] == "safe" and r["predicted"] == "safe" for r in rows)
    fp = sum(r["actual"] == "safe" and r["predicted"] == "scam" for r in rows)
    fn = sum(r["actual"] == "scam" and r["predicted"] == "safe" for r in rows)
    div = lambda a, b: a / b if b else None
    precision, recall, specificity = div(tp, tp + fp), div(tp, tp + fn), div(tn, tn + fp)
    f1 = div(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None
    return {"n": len(rows), "tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": precision,
            "recall": recall, "specificity": specificity, "f1": f1,
            "balancedAccuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None}


def bootstrap(rows, iterations=1000):
    rng = random.Random(20260915)
    values = {k: [] for k in ("precision", "recall", "specificity", "f1")}
    for _ in range(iterations):
        sample = [rows[rng.randrange(len(rows))] for _ in rows]
        m = metric(sample)
        for key in values:
            if m[key] is not None: values[key].append(m[key])
    result = {}
    for key, vals in values.items():
        if not vals:
            result[key] = None
            continue
        vals.sort()
        result[key] = [vals[int(.025 * len(vals))], vals[min(int(.975 * len(vals)), len(vals) - 1)]]
    return result


nazario = raw["nazario"]["predictions"]
synthetic = raw["synthetic"]["predictions"]
groups = {
    "nazarioHeldOut": nazario,
    "syntheticHindiHinglishScams": [r for r in synthetic if r["language"] == "hi" and r["actual"] == "scam"],
    "syntheticEnglishScams": [r for r in synthetic if r["language"] == "en" and r["actual"] == "scam"],
    "syntheticHindiHinglish": [r for r in synthetic if r["language"] == "hi"],
    "syntheticEnglish": [r for r in synthetic if r["language"] == "en"],
    "syntheticCombined": synthetic,
}
results = {
    "version": "2.0.0-research",
    "decisionRule": "SAFE below 35; SUSPICIOUS 35-69; SCAM 70-100; binary metrics count SUSPICIOUS or SCAM as positive",
    "metrics": {name: {**metric(rows), "bootstrap95CI": bootstrap(rows)} for name, rows in groups.items()},
    "latency": {
        "nazarioMedianMs": raw["nazario"]["latencyMedianMs"], "nazarioP95Ms": raw["nazario"]["latencyP95Ms"],
        "syntheticMedianMs": raw["synthetic"]["latencyMedianMs"], "syntheticP95Ms": raw["synthetic"]["latencyP95Ms"],
    },
    "artifactsSha256": manifest["hashes"],
    "notes": [
        "Nazario metrics use a deterministic, deduplicated, stratified held-out split.",
        "No exact normalized Nazario/UCI overlaps were found; the old 40-message corpus is not used by v2.",
        "Hindi/Hinglish and English scam tests are synthetic template-based robustness tests, not prevalence estimates.",
    ],
}
(OUT / "results_v2.json").write_text(json.dumps(results, indent=2) + "\n")

# Precision-recall curve on held-out Nazario using continuous local NB probability.
points = []
for threshold in [i / 100 for i in range(101)]:
    scored = [{**r, "predicted": "scam" if r["mlProbability"] >= threshold else "safe"} for r in nazario]
    m = metric(scored)
    points.append((m["recall"], m["precision"] if m["precision"] is not None else 1.0, threshold))
points.sort()
fig, ax = plt.subplots(figsize=(6.6, 4.3))
ax.plot([p[0] for p in points], [p[1] for p in points], color="#235789", linewidth=2.2)
op = metric(nazario)
ax.scatter([op["recall"]], [op["precision"]], color="#d1495b", zorder=3, label="Operating decision")
ax.set(xlabel="Recall", ylabel="Precision", xlim=(0, 1.02), ylim=(0, 1.02), title="AI Shield v2 — Held-out Nazario Precision–Recall")
ax.grid(alpha=.25); ax.legend(loc="lower left"); fig.tight_layout()
fig.savefig(OUT / "figure_pr_curve.png", dpi=200); plt.close(fig)

m = metric(nazario)
cm = [[m["tn"], m["fp"]], [m["fn"], m["tp"]]]
row_totals = [sum(cm[0]), sum(cm[1])]
fig, ax = plt.subplots(figsize=(5.5, 4.7))
ax.imshow([[v / row_totals[i] for v in row] for i, row in enumerate(cm)], cmap="Blues", vmin=0, vmax=1)
for i in range(2):
    for j in range(2):
        pct = 100 * cm[i][j] / row_totals[i]
        ax.text(j, i, f"{cm[i][j]}\n({pct:.1f}%)", ha="center", va="center", color="white" if pct > 55 else "#12263a", fontsize=12)
ax.set_xticks([0, 1], ["Predicted safe", "Predicted scam"])
ax.set_yticks([0, 1], ["Actual safe", "Actual phishing"])
ax.set_title("AI Shield v2 — Held-out Nazario Confusion Matrix")
fig.tight_layout(); fig.savefig(OUT / "figure_cm_v2.png", dpi=200); plt.close(fig)
print(json.dumps({name: metric(rows) for name, rows in groups.items()}))
