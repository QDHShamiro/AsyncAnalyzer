"""
Online (incremental) learning for the AsyncAnalyzer model.

The exact same math is implemented in PowerShell (Update-ModelOnline in
AsyncAnalyzer.ps1) so a confirmed verdict on the user's machine nudges the
local model weights. One confirmed example = one clamped SGD step. Weights are
bounded so a single mislabel can never blow up the model, and the hard rules
(verified cap, known-good/known-cheat hash) always dominate the final verdict.
"""

import math

CLAMP = 8.0


def sigmoid(z):
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def sgd_step(weights, intercept, vec, order, label, lr=0.05, l2=0.02,
             base=None, base_intercept=0.0):
    """One logistic-regression SGD step, regularised toward a `base` model
    (the well-trained embedded weights) rather than toward zero. This lets the
    tool adapt to a user's new cheats while staying anchored to the base, so it
    cannot drift into false positives on legit files. Mutates `weights` in
    place and returns (new_intercept, probability_before_update)."""
    z = intercept + sum(weights[order[i]] * vec[i] for i in range(len(order)))
    p = sigmoid(z)
    err = p - label
    for i, name in enumerate(order):
        anchor = base[name] if base is not None else 0.0
        w = weights[name] - lr * (err * vec[i] + l2 * (weights[name] - anchor))
        weights[name] = max(-CLAMP, min(CLAMP, w))
    intercept = intercept - lr * (err + l2 * (intercept - base_intercept))
    intercept = max(-CLAMP, min(CLAMP, intercept))
    return intercept, p
