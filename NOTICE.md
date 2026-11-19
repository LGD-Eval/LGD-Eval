# NOTICE — licences in this repository

Three different things live here, and they are not under one licence. This file says which
is which so that nobody has to infer it from a stray field.

| What | Licence | Where |
|---|---|---|
| Repository content — protocols, reports, charters, methodology, documentation | **CC BY 4.0** | `LICENSE` (full legal code) |
| The gate CLI shipped at `bin/lgd-eval.js` and `vendor/` | **MIT**, as maintained upstream | [`LGD-Eval/lgd-gate`](https://github.com/LGD-Eval/lgd-gate) — `package.json` describes that package |
| Theory texts (LGD three laws, normative statements) | **All Rights Reserved**, citation permitted | the theory repository's `NOTICE.md` |

## What CC BY 4.0 requires of you

Attribution is an **obligation**, not a courtesy. If you reuse, adapt or redistribute this
repository's content you must name the creator, keep the copyright notice, link to the
licence, and indicate whether you changed anything. Section 3(a) of `LICENSE` is the
operative clause; the rest of this file is a summary and does not override it.

CC BY 4.0 grants no patent or trademark rights (Section 2(b)(2)). If you need a patent
grant, the tool layer under Apache-2.0 / MIT is the relevant one, not this content licence.

## If `package.json` and this repository disagree

`package.json` here describes the `lgd-gate` npm package, which is MIT upstream. This
repository's own content is governed by `LICENSE` (CC BY 4.0). When a machine-readable
field and a licence file disagree, **the licence file wins** — that is the same rule the
rights charter states, and it is why this NOTICE exists instead of a silent edit.
