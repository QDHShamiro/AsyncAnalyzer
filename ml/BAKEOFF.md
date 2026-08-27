# Model bake-off — what actually helps, measured

Run it yourself: `python3 fetch_jars.py && python3 build_bytecode_dataset.py && python3 bakeoff.py`

## The question

Does a bigger, interaction-capable model beat the linear one, or is "big AI" decoration?
Motivation was real: with the old text features, every signal (reflection, obfuscation,
rendering) appears in **both** cheats and legitimate mods. A minimap renders; so does ESP.
A keybind mod polls input; so does KillAura. A config library uses reflection; so does a
dropper. A linear model can only add weights — it cannot express "A **and** B".

## Setup

- **239 rows, both classes real compiled bytecode.** Negatives: 77 real libraries from
  Maven Central (ASM, ByteBuddy, Netty, Guava, Kotlin, log4j, BouncyCastle, mockito…) plus
  generated legit-mod behaviours. Positives: cheat behaviours reconstructed from real cheat
  source (Meteor Client @8038a0a) and compiled by `javac`.
- **Hard negatives included on purpose**: a minimap with a mob radar, a freecam mod, a chat
  macro, a zoom mod — legitimate mods whose *behaviour* overlaps cheats. Without these the
  dataset is trivially separable and proves nothing (the first run scored 1.000 across the
  board, which was a warning sign, not a success).
- Stratified 5-fold cross-validation, pure Python.

## Result

| model | accuracy | precision | recall | F1 | false flags on 77 real libs |
|---|---|---|---|---|---|
| linear (logistic regression) | 0.975 | **1.000** | 0.875 | 0.933 | **0** |
| MLP (18→12→6→1) | 0.975 | **1.000** | 0.875 | 0.933 | **0** |
| GBDT (40 trees, depth 3) | 0.975 | **1.000** | 0.875 | 0.933 | **0** |

**All three are identical.** The bigger models add nothing measurable. The behavioural
features do the work, not the model — so the simple one ships. It is smaller, it stays
compatible with the online-learning step, and claiming a neural network here would be
marketing, not engineering.

## What the misses actually are

Every one of the 6 missed cheats is a **pure-ESP** variant: `render + entityscan`. That is
the same behaviour as a legitimate mob-radar minimap, because **ESP and a mob radar really
do the same thing**. The information needed to separate them is not in the bytecode. No
model size fixes that.

So the design follows the evidence:

| behaviour | what it means | verdict |
|---|---|---|
| rotation **and** forged movement packet | the aim/killaura fingerprint; no legit mod fakes its own movement packet | **Confirmed** |
| decrypt **then** define a class | dropper / ghost loader | **Confirmed** |
| Java agent / retransform | injector | **Confirmed** |
| render **and** entity sweep | ESP *or* a mob radar — genuinely ambiguous | **Review**, never an accusation |

Deciding the ambiguous case needs *identity*, not more AI — which is exactly what the hash
verification is for. A verified minimap is Clean; an unverified jar doing the same thing is
worth a human look.

## Honest limits

- The positives are **reconstructions** compiled from real cheat source, not captured cheat
  binaries. This repo ships no cheat samples. The constant pools come from a real compiler,
  so the structure is genuine, but a real Doomsday build could differ.
- 239 rows is small. Precision 1.000 means no legit mod was flagged *in this set*, not a
  guarantee.
- Recall 0.875 is a deliberate choice: the missing 12.5% is the ambiguous ESP class, and
  flagging it would mean false-flagging minimaps.
