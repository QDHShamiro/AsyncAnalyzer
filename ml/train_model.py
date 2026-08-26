"""
AsyncAnalyzer ML — train the cheat-probability model.

Pure-python logistic regression (no numpy / no sklearn) so it runs anywhere.
Exports:
  ml/model.json            — weights + metadata
  ml/model_ps_snippet.txt  — ready-to-paste PowerShell hashtable

The model output is a probability p(cheat) in [0,1]. AsyncAnalyzer.ps1 turns
that into a 0-100 confidence and blends it with the hard rules
(verified = safe, known hash = certain).
"""

import csv
import json
import math
import os
import random

import features
from features import FEATURE_NAMES, N_FEATURES

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(7)


def load():
    rows = []
    with open(os.path.join(HERE, "dataset.csv")) as f:
        r = csv.DictReader(f)
        for d in r:
            x = [float(d[n]) for n in FEATURE_NAMES]
            y = int(d["label"])
            rows.append((x, y, d["source"]))
    return rows


def sigmoid(z):
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def train(rows, epochs=4000, lr=0.3, l2=0.002):
    w = [0.0] * N_FEATURES
    b = 0.0
    n = len(rows)
    for _ in range(epochs):
        gw = [0.0] * N_FEATURES
        gb = 0.0
        for x, y, _src in rows:
            z = b + sum(w[i] * x[i] for i in range(N_FEATURES))
            p = sigmoid(z)
            err = p - y
            for i in range(N_FEATURES):
                gw[i] += err * x[i]
            gb += err
        for i in range(N_FEATURES):
            w[i] -= lr * (gw[i] / n + l2 * w[i])
        b -= lr * (gb / n)
    return w, b


def predict(w, b, x):
    return sigmoid(b + sum(w[i] * x[i] for i in range(N_FEATURES)))


def evaluate(w, b, rows, thr=0.5):
    tp = tn = fp = fn = 0
    for x, y, _ in rows:
        p = 1 if predict(w, b, x) >= thr else 0
        if p == 1 and y == 1:
            tp += 1
        elif p == 0 and y == 0:
            tn += 1
        elif p == 1 and y == 0:
            fp += 1
        else:
            fn += 1
    acc = (tp + tn) / max(1, len(rows))
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    return acc, prec, rec, (tp, tn, fp, fn)


def main():
    rows = load()
    random.shuffle(rows)
    cut = int(len(rows) * 0.8)
    train_rows, test_rows = rows[:cut], rows[cut:]

    w, b = train(train_rows)

    print("=== Feature weights (higher = more cheat-like) ===")
    for name, weight in sorted(zip(FEATURE_NAMES, w), key=lambda t: -t[1]):
        print(f"  {name:16s} {weight:+.3f}")
    print(f"  {'(intercept)':16s} {b:+.3f}")

    acc, prec, rec, cm = evaluate(w, b, test_rows)
    print("\n=== Held-out test metrics ===")
    print(f"  accuracy  {acc:.3f}")
    print(f"  precision {prec:.3f}   (few false alarms = few false flags)")
    print(f"  recall    {rec:.3f}   (few missed cheats)")
    print(f"  confusion tp={cm[0]} tn={cm[1]} fp={cm[2]} fn={cm[3]}")

    # sanity: every REAL library jar must score low (these are the FP traps)
    print("\n=== Real library jars (must be LOW = not cheat) ===")
    worst = 0.0
    seen = set()
    for x, y, src in rows:
        if src.startswith("real:") and src not in seen:
            seen.add(src)
            p = predict(w, b, x)
            worst = max(worst, p)
            flag = "  <-- HIGH!" if p >= 0.5 else ""
            print(f"  {src[5:]:22s} p(cheat)={p:.3f}{flag}")
    print(f"  worst real-jar score: {worst:.3f}")

    # bump the version on every retrain so clients can auto-update to a newer
    # model (the number only ever needs to go up)
    version = 2
    prev = os.path.join(HERE, "model.json")
    if os.path.exists(prev):
        try:
            version = int(json.load(open(prev)).get("version", 1)) + 1
        except Exception:
            version = 2

    model = {
        "type": "logistic_regression",
        "version": version,
        "feature_order": FEATURE_NAMES,
        "intercept": round(b, 6),
        "weights": {n: round(wi, 6) for n, wi in zip(FEATURE_NAMES, w)},
        "test_accuracy": round(acc, 4),
        "test_precision": round(prec, 4),
        "test_recall": round(rec, 4),
        "n_train": len(train_rows),
        "n_test": len(test_rows),
        "n_real_jars": sum(1 for _, _, s in rows if s.startswith("real:")) // 3,
    }
    with open(os.path.join(HERE, "model.json"), "w") as f:
        json.dump(model, f, indent=2)
    print("\nwrote ml/model.json")

    # PowerShell snippet
    lines = []
    lines.append("$script:mlIntercept = " + repr(round(b, 6)))
    lines.append("$script:mlFeatureOrder = @(" +
                 ",".join("'%s'" % n for n in FEATURE_NAMES) + ")")
    lines.append("$script:mlWeights = @{")
    for n, wi in zip(FEATURE_NAMES, w):
        lines.append("    '%s' = %s" % (n, repr(round(wi, 6))))
    lines.append("}")
    snippet = "\n".join(lines) + "\n"
    with open(os.path.join(HERE, "model_ps_snippet.txt"), "w") as f:
        f.write(snippet)
    print("wrote ml/model_ps_snippet.txt")


if __name__ == "__main__":
    main()
