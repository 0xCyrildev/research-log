# How I read a codebase

The process behind entries in this repo, and behind audit work more broadly. No magic, no checklist worship, just a repeatable sequence that catches more than skimming for `require` statements.

## 1. Model the system before touching code

Before line-by-line review: what are the actors, what are the trust boundaries, what state transitions exist, what's the intended invariant set. For Move/Sui this means owned vs shared object boundaries and ability constraints. For EVM this means access control surface and external call graph. Skip this step and you're just reading text, not a system.

## 2. Look for composed attacks, not checklist items

A checklist catches "is this function missing an access modifier." It does not catch "these three individually-safe functions produce an unsafe state when called in this order." Most of the highest-severity findings in real audits are economic or state-machine composition bugs, not single-line mistakes. If the bug were that obvious, the dev would've caught it too.

## 3. Cross-check against a class list, but don't stop there

Maintain and run a full exploit and bug-class checklist (Solidity/EVM and Move/Sui/Aptos) per target as a floor, not a ceiling. The checklist catches known patterns fast, which frees up time budget for the novel composition analysis that actually earns the fee.

## 4. Every finding gets: trigger precondition, exploit path, root cause, severity, fix

If any of these five are missing, the finding isn't done. "Root cause" specifically, not just "this input isn't validated" but why that validation gap exists architecturally. Anyone can spot the symptom.

## 5. Adversarial pass at the end

After the systematic pass, re-read as an attacker with unlimited capital and no ethics. What's the most damage extractable, not just the first bug found. This is the pass that separates a report someone forwards to legal from one that gets filed and forgotten.

## 6. Treat unverified findings as hypotheses

A finding without a working PoC (Foundry test, `sui move test`, or equivalent) is "Hypothesis, needs manual verification," not a confirmed bug. This applies to my own tooling output too. Automated static analysis findings don't get called Critical or High until a PoC passes and a human confirms it. Confidence is earned, not asserted.
