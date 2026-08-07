# research-log

Security research notes — Web3 and Web2. Exploit postmortems, design flaw patterns, and tooling built off findings.

## Why this exists

Most public writeups stop at "here's what happened and here's the patch." That's not analysis, it's a summary. This repo goes one layer deeper on each entry: root cause, what the patch doesn't fix, and where else the same pattern shows up.

Every entry that motivated a tool feature links to the tool. Findings aren't just observed here — some get turned into static checks, fuzzers, or forensics scripts.

## Index

### Web3
| Entry | Chain/Stack | Class | Status |
|---|---|---|---|
| _pending_ | | | |

### Web2
| Entry | Stack | Class | Status |
|---|---|---|---|
| _pending_ | | | |

## Methodology

See [`methodology/how-i-read-a-codebase.md`](methodology/how-i-read-a-codebase.md) for the process behind these writeups.

## Related tooling

- [`sui-sec`](https://github.com/0xCyrildev/sui-sec) — static bytecode scanner for Sui Move
- `necropsy` — EVM post-exploit forensics (call-tree + fund-flow tracing)
- `flank` — Web3 attack-surface recon (Immunefi/Sherlock pre-audit)
- `sui-invariant-fuzzer` — invariant fuzzer for Sui Move packages

## Entry format

New entries follow [`_template.md`](_template.md). Every entry is dated and tagged with the vuln class it belongs to, so patterns across entries stay searchable.
