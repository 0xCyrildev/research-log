# research-log

Web3 and Web2 security research. Exploit postmortems, design flaw patterns, and the tooling built off what I find.

## Why this exists

Most public writeups stop at "here's what happened, here's the patch." That's a summary, not analysis, and the internet already has enough of those.

I'm not interested in restating a postmortem that's already public. Every entry here goes one layer past that: root cause, what the patch doesn't actually fix, and where else I've seen the same failure class show up. If I can't say something the original writeup didn't already say, I don't publish it.

If a finding motivated a feature in one of my tools, it's linked here. I don't just write about bug classes, I build things that catch them before they become someone else's bad week.

## Index

### Web3
| Entry | Chain/Stack | Class | Status |
|---|---|---|---|
| [Ostium: $23.75M for a fake $5,000 Bitcoin](web3/exploit-postmortems/ostium-oracle-exploit.md) | Arbitrum / EVM | oracle trust, off-chain signer compromise | published |

### Web2
| Entry | Stack | Class | Status |
|---|---|---|---|
| [Twitch switched: the production flag config ships in the APK](web2/twitch-switched.md) | Android APK / bundled web SPA / Eppo | information disclosure, client-side decision authority | published |

## Methodology

[`methodology/how-i-read-a-codebase.md`](methodology/how-i-read-a-codebase.md) covers the actual process behind these writeups and my audit work generally. Not a checklist. Checklists catch known patterns, not composed attacks, and most of the real damage in a serious audit comes from composition, not a missing modifier on line 40.

## Related tooling

- [`sui-sec`](https://github.com/0xCyrildev/sui-sec), static bytecode scanner for Sui Move
- `necropsy`, EVM post-exploit forensics: call-tree and fund-flow tracing
- `flank`, Web3 attack-surface recon for Immunefi/Sherlock pre-audit work
- `sui-invariant-fuzzer`, invariant fuzzer for Sui Move packages

## Entry format

New entries follow [`_template.md`](_template.md): what happened, why it worked, what the fix misses, where else the pattern shows up, what it means for tooling. If an entry can't answer all five, it's not done yet, and it doesn't ship half-baked.
