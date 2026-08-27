"""
Honest model comparison on the behavioural dataset.

The question this answers: does an interaction-capable model actually beat the
linear one on THIS data, or is "bigger AI" just decoration? Every behaviour in
the feature set appears in both classes (a minimap renders, so does ESP), so a
linear model has to separate them by weight alone, which it cannot do for AND.

Stratified 5-fold cross-validation, pure Python (no numpy), and the metric that
matters most for this tool is reported separately: false positives on the REAL
library jars, because a false flag is the one failure the tool must not have.
"""
import csv, math, os, random, sys

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(1234)


def load():
    rows = list(csv.DictReader(open(os.path.join(HERE, "dataset_bytecode.csv"))))
    feats = [k for k in rows[0] if k not in ("label", "name")]
    X = [[float(r[f]) for f in feats] for r in rows]
    y = [int(r["label"]) for r in rows]
    real = [not r["name"].startswith("v") or not r["name"][1:-4].isdigit() for r in rows]
    return X, y, feats, real


def folds(y, k=5):
    idx0 = [i for i, v in enumerate(y) if v == 0]
    idx1 = [i for i, v in enumerate(y) if v == 1]
    random.shuffle(idx0); random.shuffle(idx1)
    out = [[] for _ in range(k)]
    for i, v in enumerate(idx0): out[i % k].append(v)
    for i, v in enumerate(idx1): out[i % k].append(v)
    return out


def sig(z):
    if z < -60: return 0.0
    if z > 60: return 1.0
    return 1.0 / (1.0 + math.exp(-z))


# ----------------------------------------------------------------- logistic ---
def fit_logistic(X, y, epochs=600, lr=0.3, l2=1e-3):
    n, d = len(X), len(X[0])
    w = [0.0] * d; b = 0.0
    for _ in range(epochs):
        gw = [0.0] * d; gb = 0.0
        for xi, yi in zip(X, y):
            p = sig(b + sum(w[j] * xi[j] for j in range(d)))
            e = p - yi
            for j in range(d): gw[j] += e * xi[j]
            gb += e
        for j in range(d): w[j] -= lr * (gw[j] / n + l2 * w[j])
        b -= lr * gb / n
    return ("logistic", w, b)


def pred_logistic(m, x):
    _, w, b = m
    return sig(b + sum(w[j] * x[j] for j in range(len(x))))


# ---------------------------------------------------------------------- MLP ---
def fit_mlp(X, y, hidden=(12, 6), epochs=900, lr=0.08, l2=1e-4):
    d = len(X[0]); sizes = [d] + list(hidden) + [1]
    W = [[[random.gauss(0, 1.0 / math.sqrt(sizes[l])) for _ in range(sizes[l])]
          for _ in range(sizes[l + 1])] for l in range(len(sizes) - 1)]
    B = [[0.0] * sizes[l + 1] for l in range(len(sizes) - 1)]

    def forward(x):
        acts = [x]
        for l in range(len(W)):
            z = [B[l][i] + sum(W[l][i][j] * acts[-1][j] for j in range(len(acts[-1])))
                 for i in range(len(W[l]))]
            acts.append([math.tanh(v) for v in z] if l < len(W) - 1 else [sig(z[0])])
        return acts

    order = list(range(len(X)))
    for ep in range(epochs):
        random.shuffle(order)
        for i in order:
            x, yi = X[i], y[i]
            acts = forward(x)
            delta = [acts[-1][0] - yi]
            for l in range(len(W) - 1, -1, -1):
                a_in = acts[l]
                nd = [0.0] * len(a_in)
                for o in range(len(W[l])):
                    g = delta[o]
                    for j in range(len(a_in)):
                        nd[j] += g * W[l][o][j]
                        W[l][o][j] -= lr * (g * a_in[j] + l2 * W[l][o][j])
                    B[l][o] -= lr * g
                if l > 0:
                    delta = [nd[j] * (1 - acts[l][j] ** 2) for j in range(len(a_in))]
    return ("mlp", W, B)


def pred_mlp(m, x):
    _, W, B = m
    a = x
    for l in range(len(W)):
        z = [B[l][i] + sum(W[l][i][j] * a[j] for j in range(len(a))) for i in range(len(W[l]))]
        a = [math.tanh(v) for v in z] if l < len(W) - 1 else [sig(z[0])]
    return a[0]


# --------------------------------------------------------------------- GBDT ---
def _stump(X, g, idx, depth):
    """depth-limited regression tree on gradients"""
    if depth == 0 or len(idx) < 4:
        return ("leaf", sum(g[i] for i in idx) / max(len(idx), 1))
    best = None
    for f in range(len(X[0])):
        vals = sorted({X[i][f] for i in idx})
        if len(vals) < 2: continue
        for k in range(1, len(vals)):
            thr = (vals[k - 1] + vals[k]) / 2.0
            L = [i for i in idx if X[i][f] <= thr]; R = [i for i in idx if X[i][f] > thr]
            if not L or not R: continue
            ml = sum(g[i] for i in L) / len(L); mr = sum(g[i] for i in R) / len(R)
            err = sum((g[i] - ml) ** 2 for i in L) + sum((g[i] - mr) ** 2 for i in R)
            if best is None or err < best[0]: best = (err, f, thr, L, R)
    if best is None:
        return ("leaf", sum(g[i] for i in idx) / len(idx))
    _, f, thr, L, R = best
    return ("split", f, thr, _stump(X, g, L, depth - 1), _stump(X, g, R, depth - 1))


def _tval(t, x):
    while t[0] == "split":
        t = t[3] if x[t[1]] <= t[2] else t[4]
    return t[1]


def fit_gbdt(X, y, n_trees=40, depth=3, lr=0.3):
    base = math.log((sum(y) + 1.0) / (len(y) - sum(y) + 1.0))
    F = [base] * len(X); trees = []
    for _ in range(n_trees):
        g = [y[i] - sig(F[i]) for i in range(len(X))]
        t = _stump(X, g, list(range(len(X))), depth)
        trees.append(t)
        for i in range(len(X)): F[i] += lr * _tval(t, X[i])
    return ("gbdt", base, trees, lr)


def pred_gbdt(m, x):
    _, base, trees, lr = m
    return sig(base + lr * sum(_tval(t, x) for t in trees))


MODELS = {"linear": (fit_logistic, pred_logistic),
          "mlp":    (fit_mlp,      pred_mlp),
          "gbdt":   (fit_gbdt,     pred_gbdt)}


def main():
    X, y, feats, real = load()
    print("dataset: %d rows, %d cheat, %d clean, %d features\n" % (
        len(X), sum(y), len(y) - sum(y), len(feats)))
    F = folds(y, 5)
    results = {}
    for name, (fit, pred) in MODELS.items():
        tp = fp = fn = tn = 0
        real_fp = real_n = 0
        for k in range(len(F)):
            test = set(F[k]); tr = [i for i in range(len(X)) if i not in test]
            m = fit([X[i] for i in tr], [y[i] for i in tr])
            for i in test:
                p = pred(m, X[i]) >= 0.5
                if p and y[i]: tp += 1
                elif p and not y[i]:
                    fp += 1
                    if real[i]: real_fp += 1
                elif not p and y[i]: fn += 1
                else: tn += 1
                if real[i] and not y[i]: real_n += 1
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        acc = (tp + tn) / float(len(X))
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        results[name] = (acc, prec, rec, f1, real_fp, real_n)
        print("  %-7s acc=%.3f  precision=%.3f  recall=%.3f  F1=%.3f   "
              "false flags on REAL libs: %d/%d" % (name, acc, prec, rec, f1, real_fp, real_n))
    print()
    best = max(results, key=lambda k: (results[k][4] == 0, results[k][3]))
    print("winner: %s  (zero false flags first, then F1)" % best)
    return 0


if __name__ == "__main__":
    sys.exit(main())
