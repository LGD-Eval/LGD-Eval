# AI-Index Gate

A **deterministic, offline, reproducible** gate for static AI artifacts: repository docs, skill files, tool descriptions, prompt templates.
It answers one question CI can act on: *does this artifact contain instructions that act on the reader rather than describe something?*

```
python demo.py          # six assertions, ~10 s, no network, no API key
```

Exit code is the verdict: `0` clean · `1` blocking findings · `2` bad usage.

## Why another gate

Existing tools either put the text through a model (nondeterministic, needs a key, cannot run in fork PRs) or state they are not meant for system-prompt-like text. This gate targets exactly that gap:

| | promptfoo | llm-guard | garak | AI-Index Gate |
|---|---|---|---|---|
| Scans | model output | user input | model output | **repo docs / skills** |
| Needs model or key | yes | yes | **required** | **no** |
| Deterministic | sampling | model-dependent | model-dependent | **same input → same output** |
| Reproducible evidence pack | report | no | hitlog | **object + engine hash, `VERDICT: MATCH`** |
| Signature / attestation | share link | no | no | **Ed25519, AI self-sign refused** |
| Published false-positive rate | no | no | no | **P0 7 → 0 on 517k chars** |

*llm-guard's own docs: "We don't recommend using this scanner for system prompts. It's designed to work with user inputs."*

## What it does

1. **Rule engine** — 81 rules / 143 patterns across `core`, `intent`, `intent2`, `zh`, `misc` packs; OWASP LLM Top-10 tagged. Pure stdlib.
2. **Context-aware noise reduction** (`--context-aware`) — documentation verbs, limitation statements, quoted spans and capability tables are downgraded to P3 while keeping `original_level`, `context_signals` and `downgrade_rule`.
3. **Adjudicator** (`--adjudicate`) — a second, independent judge (EN/ZH/FR/DE verb and object lexicons, external URLs, quote spans, identifier masking). It also scans lines the regex missed, so *no finding is silently skipped*.
4. **Hard-payload list** — never downgraded: `=cmd|`, `grant yourself admin`, `bypass the approval`, zero-width characters (U+200B/C/D, U+2060), markdown image URLs carrying `data/leak/payload/conv` parameters.
5. **Three routes** — `BLOCK` / `REVIEW` (human queue) / `PASS`. Uncertainty never becomes PASS.
6. **Evidence pack** — embeds the LF-normalised object text plus object and engine SHA-256, so a third party can recompute the verdict offline and get `MATCH`.
7. **Release gate** — `release.py` runs engine self-test, dual regression, gate scan and signature check, and writes `release-manifest.json` with `READY` / `BLOCKED`.
8. **Human-only signing** — `sign.py` refuses to sign any artifact whose text still contains a draft marker; `--human` records `human_attested=true`.

## Measured numbers (all reproducible in-repo)

| What | Result |
|---|---|
| Evidence packs, 6 upstream READMEs | `VERDICT: MATCH` on each |
| Competitor READMEs, 95,827 chars | P0 15 → **0** |
| Benign skills, 59 files / 517,358 chars | P0 7 → **0**, P1 5 left for review |
| Attack samples, 20 hand-built | 20/20 detected, 0 lost after noise reduction |
| Blind set v4, 7 samples, never tuned on | 3/7 detected, union with adjudicator 6/7 |
| Cross-language attacks (ES/JA/RU/PT) | 0/6 auto-detected, **0/6 silently passed** (all routed to review) |
| Red team, 10 attacks disguised as docs | context-only: 7/10 passed → with adjudicator: **BLOCK 10/10, 0 passed** |
| AI signing a draft | refused, exit 3 |
| Unsigned artifact at release | `BLOCKED` |
| Signed copy at release | `READY` |

## The one rule we will not break

**The noise-reduction layer must never be enabled alone.** Red-team measurement: with `--context-aware` only, 7 of 10 attacks disguised as documentation passed the gate. `gate.py` refuses to run `--adjudicate` in a degraded mode, and the shipped workflow uses both flags together.

## What this does not do

- It does not red-team a model. Use promptfoo or garak for that.
- It does not claim high recall on languages outside EN/ZH/FR/DE; those go to the human queue.
- It does not claim zero false positives. It publishes its numbers instead, including the failures.
- The semantic adjudicator (`llm_adjudicator.py`) is an interface with a strict JSON contract, SHA-256 response cache and a self-test; **it has not been measured against a live model** in this repository.

## Usage

```bash
# scan a local artifact
python gate.py --file README.md --context-aware --adjudicate

# scan a GitHub repo file and write an evidence pack
python gate.py --repo owner/name --path README.md --context-aware --adjudicate --out pack.json

# verify a pack offline (any machine)
python gate.py --verify pack.json

# release gate
python release.py --file artifact.md --sig artifact.sig
```

Core scanning and verification need **Python 3 stdlib only**. Signing needs `cryptography`.

## Repository map

```
scanner.py         rule engine (v0.3.4)
adjudicator.py     second judge
llm_adjudicator.py optional semantic layer (needs an API key)
gate.py            fetch / scan / pack / verify / regression / routes
release.py         four-gate preflight → release-manifest.json
sign.py            Ed25519 sign / verify, human attestation
demo.py            six-assertion self-demo, offline
fixtures/          benign, attack, cross-language, red-team corpora
```

License and contribution terms: see `LICENSE` / `CONTRIBUTING.md`.
