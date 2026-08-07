# [Title]

**Date:** YYYY-MM-DD
**Category:** web3 / web2
**Vuln class:** e.g. access-control, oracle-manipulation, reentrancy, auth-bypass
**Chain/Stack:** e.g. EVM, Sui Move, Move, cloud infra, etc.

---

## What happened

Facts only. What was exploited, how much was lost/at risk, timeline if relevant. Keep this section tight — this is the part everyone else already wrote.

## Why it worked

Root cause. Not "bad code" — the actual mechanism. What assumption broke, what invariant was missing, what trust boundary was crossed.

## What the obvious fix misses

The patch stops the specific exploit. What does it not stop? What's the next variant of this bug an attacker could still pull off against the patched code?

## Where else this pattern exists

The differentiator section. Have you seen this class in an audit, another protocol, another codebase? Connect it. This is what separates analysis from news aggregation.

## Tooling

Does this motivate a check in `sui-sec`, a heuristic in `flank`, a trace pattern in `necropsy`? Link it. If nothing yet, note it as a backlog item.

---

*Sources: [links to primary sources — postmortem, tx hash, disclosure]*
