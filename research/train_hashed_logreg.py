#!/usr/bin/env python3
"""Train AI Shield's compact, offline hashed logistic-regression model.

Only Python's standard library is required. The output is a Base64-encoded
int8 vector suitable for direct import into an MV3 extension or browser bundle.
No dataset text is shipped in the generated model.
"""
from __future__ import annotations

from collections import defaultdict
import base64
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "research" / "data"
OUT = ROOT / "research" / "v3"
SEED = 20260920
DIMENSION = 8192
EPOCHS = 4
LEARNING_RATE = 0.08
L2 = 0.0008


def normalise(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").lower()).strip()


def fnv1a(value: str) -> int:
    value_hash = 0x811C9DC5
    for char in value:
        value_hash ^= ord(char)
        value_hash = (value_hash * 0x01000193) & 0xFFFFFFFF
    return value_hash


def feature_buckets(text: str) -> dict[int, float]:
    value = normalise(text)[:512]
    tokens = re.findall(r"[^\W_]+", value, flags=re.UNICODE)[:600]
    model_tokens = tokens + [f"{left}_{right}" for left, right in zip(tokens, tokens[1:])]
    keys = [f"w:{token}" for token in model_tokens]
    for width in (3, 4):
        keys.extend(f"c{width}:{value[index:index + width]}" for index in range(len(value) - width + 1))
    result: dict[int, float] = defaultdict(float)
    for key in keys:
        value_hash = fnv1a(key)
        result[value_hash % DIMENSION] += -1 if value_hash & 0x80000000 else 1
    return {bucket: math.copysign(math.log1p(abs(count)), count) for bucket, count in result.items()}


def sigmoid(value: float) -> float:
    return 1 / (1 + math.exp(-max(-30, min(30, value))))


def main() -> None:
    source = DATA / "Nazario_5.csv"
    rows, seen = [], set()
    csv.field_size_limit(sys.maxsize)
    with source.open(encoding="utf-8", errors="replace") as stream:
        for row in csv.DictReader(stream):
            text = "\n".join(filter(None, [row.get("subject"), row.get("body"), row.get("urls")]))
            key = normalise(text)
            if key and key not in seen:
                seen.add(key)
                rows.append((text, 1 if row["label"] == "1" else 0))

    rng = random.Random(SEED)
    selected = []
    for label in (0, 1):
        group = [row for row in rows if row[1] == label]
        rng.shuffle(group)
        selected.extend(group[:1000])
    rng.shuffle(selected)
    train, test = selected[:1600], selected[1600:]

    weights, bias = [0.0] * DIMENSION, 0.0
    for _ in range(EPOCHS):
        rng.shuffle(train)
        for text, label in train:
            features = feature_buckets(text)
            logit = bias + sum(weights[bucket] * value for bucket, value in features.items())
            error = sigmoid(logit) - label
            bias -= LEARNING_RATE * error
            for bucket, value in features.items():
                weights[bucket] -= LEARNING_RATE * (error * value + L2 * weights[bucket])

    max_abs = max(max(abs(value) for value in weights), 1e-9)
    scale = max_abs / 120
    quantized = bytes(max(0, min(255, round(value / scale) + 128)) for value in weights)
    payload = {
        "schemaVersion": 3,
        "algorithm": "hashed-logistic-regression-int8",
        "dimension": DIMENSION,
        "quantizationScale": scale,
        "bias": bias,
        "weightsBase64": base64.b64encode(quantized).decode("ascii"),
        "training": {
            "source": "Nazario_5.csv",
            "sourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "seed": SEED,
            "split": "stratified-80-20",
            "trainRows": len(train),
            "testRows": len(test),
            "warning": "Train only after adding reviewed Indian UPI, KYC and banking examples; evaluate by language and scam family before release.",
        },
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "model.json").write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    print(json.dumps({"bytes": (OUT / "model.json").stat().st_size, "train": len(train), "test": len(test)}))


if __name__ == "__main__":
    main()
