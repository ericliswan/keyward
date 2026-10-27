# ADR 0002: Argon2id default parameters

- Status: accepted
- Date: 2026-10-28

## Context

The first draft of the design used RFC 9106's second recommended option, 64 MiB with 3 passes and 4 lanes, and planned to calibrate it on real hardware. The target is an unlock of 0.5–1 s: long enough to make each offline guess expensive, short enough that running one command at a time stays comfortable. The [calibration table](../DESIGN.md#calibration) shows the 64 MiB option takes about 0.14 s on the owner's Apple M1, well below the target.

## Decision

New vaults use **256 MiB, 3 passes, 4 lanes** (`KdfParams::PRODUCTION`). Argon2 stays single-threaded: the `argon2` crate's `parallel` feature stays off.

## Reasons

- **Inside the target with headroom.** About 0.6 s on the M1, so a machine twice as slow still unlocks in about 1.2 s.
- **Memory is what costs an attacker.** Each guess needs four times the memory of the 64 MiB option, which is the resource that limits GPU and ASIC attackers.
- **512 MiB with 2 passes** is already at the top of the target on the M1 (0.8–1.1 s) and needs 512 MiB free, so slower or low-memory machines would suffer.
- **RFC 9106's first option** (2 GiB, 1 pass) is below the floor's minimum of 2 passes and needs 2 GiB free.
- **No parallel lanes.** Without the `parallel` feature the lanes run one after another, so 4 lanes cost the same time as 1. Turning it on would allow more memory in the same time, but it adds `rayon` to the supply chain and a thread pool to every unlock. Attackers parallelise across guesses anyway, so they gain little from the lanes. `p_cost = 4` stays in the header, so enabling the feature later is a code change, not a format change.

## Consequences

- Unlocking a new vault needs about 256 MiB of free memory.
- The parameters are stored in each vault's header, so existing vaults keep theirs. Only `init` and `change-master` use the new default.
- Changing the default again needs a new benchmark run, an owner checkpoint and a new ADR, but no format change.
