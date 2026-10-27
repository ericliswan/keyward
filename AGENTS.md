# AGENTS.md — Build Instructions for `pwv`

This file tells a coding agent exactly how to build **`pwv`**, a local command-line password manager, as a professional GitHub repository: issues, branches, small Conventional Commits, pull requests with CI, milestones, tagged releases and complete documentation.

Read the whole file before the first command. Work through the milestones **in order**, one pull request at a time. Never skip the tests or the security checklist to go faster.

---

## 0. How to use this file

- **Unit of work = one issue → one branch → one PR.** Each PR in Section 8 lists its branch name, suggested commits and acceptance criteria.
- **Stop at every 🛑 HUMAN CHECKPOINT.** Post a summary in the PR (or an issue) and wait for the repository owner to reply before merging. These checkpoints exist because the owner must be able to explain every design decision in interviews.
- **When blocked or unsure** (a library API changed, a requirement is ambiguous, a test can't be made to pass honestly): open an issue labelled `question`, describe the options, and stop. Do not guess on anything touching cryptography or the file format.
- **Flag tasks that need more reasoning effort.** Before starting a task that would clearly benefit from high or max effort (new crypto or file-format code, 🛑 checkpoint material, security test design, threat-model writing, hard cross-platform bugs), stop and tell the owner which level and why, so they can switch. Routine work (docs edits, dependency bumps, merging green PRs) does not need this.
- **Keep this file current.** If a decision changes, update this file in the same PR.

---

## 1. Ground rules (non-negotiable)

### Security
1. **No custom cryptography.** Only call vetted library primitives (Argon2id, XChaCha20-Poly1305, OS CSPRNG). No home-made ciphers, padding schemes, XOR layers, or "double encryption".
2. **All crypto lives in `pwv-core::kdf` and `pwv-core::crypto`.** No other module calls a crypto crate directly.
3. **Secrets never appear in** command-line arguments, environment variables, logs, `Debug` output, panic messages, error messages or test snapshots.
4. **`#![forbid(unsafe_code)]`** in every crate.
5. **Never commit real secrets**, sample vaults made with real passwords, or `.env` files. Test vaults are generated in temp directories at test time.

### Honest history
6. **Commits reflect the actual work.** Never backdate commits (`GIT_AUTHOR_DATE`, `--date`), invent co-authors, or rewrite history to fake a longer timeline. "Regular commits" means small, genuine, incremental commits — not manufactured ones.
7. **Never force-push to `main`.** Force-pushing your own feature branch before merge is fine.
8. **Be transparent.** The README includes a short "Development process" note stating that the project was built with AI-agent assistance under the owner's design and review. Reviewers respect this; discovering it later costs credibility.

### Quality
9. Every PR leaves `main` green: `fmt`, `clippy -D warnings`, tests, and `cargo deny` all pass.
10. Every bug fix comes with a regression test.
11. Public items in `pwv-core` have doc comments.

---

## 2. Project specification

### What it is
A local-only CLI password manager. A master password is stretched with **Argon2id** (random salt) into a 256-bit key that encrypts the whole vault with **XChaCha20-Poly1305**. The plaintext header (format version, KDF parameters, salt, nonce) is authenticated as **associated data**, so any modification to any byte of the file makes decryption fail.

### Commands (v1.0)
| Command | Behaviour |
| --- | --- |
| `pwv init` | Prompt for master password twice, check strength, create empty vault. Refuse to overwrite without `--force`. |
| `pwv add <site>` | Prompt for username, password (or `--generate`), notes. |
| `pwv get <site>` | Copy password to clipboard, clear after 30 s. `--show` prints it. `--timeout <s>`, `--no-clipboard`. |
| `pwv list` | Site + username only. `--search <text>`. |
| `pwv edit <site>` | Edit one field at a time (`--username`, `--password`, `--notes` prompt for the new value). |
| `pwv delete <site>` | Confirm, then remove. `--yes` skips the prompt. |
| `pwv change-master` | New password, new salt, re-encrypt. |
| `pwv gen` | Print a generated password. `--length`, `--no-lower/--no-upper/--no-digits/--no-symbols`, `--no-ambiguous`, `--passphrase <words>`. |

Global flags: `--vault <PATH>` (env `PWV_VAULT` may hold the **path only**), `--password-stdin` (automation/tests only; reads one line from stdin).

When several entries match `<site>`, list them with an index and ask which one.

### Exit codes
`0` success · `1` general/user error · `2` usage error (clap default) · `3` authentication or integrity failure.

### Vault file format v1 (all integers little-endian)

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | `b"PWVF"` |
| 4 | 1 | `format_version` | `1` |
| 5 | 1 | `kdf_id` | `1` = Argon2id v0x13 |
| 6 | 4 | `m_cost_kib` | u32 |
| 10 | 4 | `t_cost` | u32 |
| 14 | 4 | `p_cost` | u32 |
| 18 | 16 | `salt` | random |
| 34 | 1 | `cipher_id` | `1` = XChaCha20-Poly1305 |
| 35 | 24 | `nonce` | random, fresh on **every** save |
| 59 | n + 16 | `ciphertext ‖ tag` | AEAD output |

- `HEADER_LEN = 59`. **AAD = bytes `[0..59)`** — the entire header.
- Plaintext = UTF-8 JSON of `Vault`:
  ```json
  {"schema_version":1,"entries":[{"id":"<uuid v4>","site":"","username":"","password":"","notes":"","created_at":"<RFC 3339>","updated_at":"<RFC 3339>"}]}
  ```
- **Salt** changes only on `init` and `change-master`. **Nonce** changes on every save.

### KDF parameters
| Profile | m_cost | t_cost | p_cost | Notes |
| --- | --- | --- | --- | --- |
| Default (production) | 65 536 KiB (64 MiB) | 3 | 4 | RFC 9106 second recommended option; calibrate in PR #10 |
| Floor (reject below) | 19 456 KiB | 2 | 1 | OWASP minimum |
| Ceiling (reject above) | 4 194 304 KiB (4 GiB) | 10 | 16 | Prevents a malicious header from exhausting memory |
| Test-only | 8 KiB-scale values | 1 | 1 | Only with cargo feature `insecure-test-kdf`, never default |

### Errors (`pwv-core::Error`, via `thiserror`)
`Format` (bad magic/length) · `UnsupportedVersion` · `ParamsOutOfRange` · `Decrypt` (message exactly: **"wrong password or corrupted vault"** — never distinguish the two) · `Io` · `Serde`. Errors never include secret material.

---

## 3. Tech stack

Use the **latest stable release** of each crate at the time of work and check its docs.rs page — several of these (notably `chacha20poly1305` 0.10 → 0.11 and `rand`) changed APIs recently, so older examples may not compile. Record exact versions in `Cargo.lock` (committed) and in the README.

| Purpose | Crate |
| --- | --- |
| CLI parsing | `clap` (derive) |
| Hidden prompt | `rpassword` |
| KDF | `argon2` (RustCrypto) |
| AEAD | `chacha20poly1305` (`XChaCha20Poly1305`) |
| Randomness | `rand` with `OsRng` / `getrandom` |
| Secret hygiene | `zeroize`, `secrecy` |
| Serialization | `serde`, `serde_json` |
| IDs / time | `uuid` (v4, serde), `time` (RFC 3339, serde) |
| Errors | `thiserror` (core), `anyhow` (CLI) |
| Paths / atomic write | `directories`, `tempfile` |
| Clipboard | `arboard` |
| Ctrl-C handling | `ctrlc` |
| Master-password strength | `zxcvbn` |
| Tests | `proptest`, `assert_cmd`, `predicates`, `tempfile`, `hex-literal` |
| Fuzzing | `cargo-fuzz` (nightly, `fuzz/` directory) |
| Coverage | `cargo-llvm-cov` |
| Supply chain | `cargo-deny` |
| Changelog | `git-cliff` |
| Releases | `cargo-dist` |
| Stretch | `reqwest` (blocking, rustls), `sha1`, `totp-rs`, `csv`, `ratatui` + `crossterm`, `tauri` 2 |

---

## 4. Repository layout (target state at v1.0)

```
pwv/
├── .github/
│   ├── workflows/ci.yml
│   ├── workflows/release.yml          # generated by cargo-dist
│   ├── ISSUE_TEMPLATE/bug_report.yml
│   ├── ISSUE_TEMPLATE/feature_request.yml
│   ├── ISSUE_TEMPLATE/config.yml
│   ├── pull_request_template.md
│   ├── dependabot.yml
│   └── CODEOWNERS
├── crates/
│   ├── pwv-core/                      # library: all crypto, format, storage, generator
│   │   ├── src/{lib.rs,error.rs,kdf.rs,header.rs,crypto.rs,model.rs,storage.rs,generator.rs}
│   │   ├── src/wordlist/eff_large.txt # EFF wordlist (CC BY 3.0 US, attribute in README)
│   │   └── tests/{roundtrip.rs,tamper.rs,kat.rs,generator.rs}
│   └── pwv-cli/                       # binary `pwv`
│       ├── src/{main.rs,cli.rs,prompt.rs,clipboard.rs,output.rs}
│       ├── src/commands/{init,add,get,list,edit,delete,change_master,gen}.rs
│       └── tests/cli.rs
├── fuzz/fuzz_targets/parse_header.rs
├── docs/
│   ├── DESIGN.md
│   ├── THREAT_MODEL.md
│   ├── decisions/0001-xchacha20-poly1305.md   # ADRs
│   └── demo.tape                       # VHS script for the demo GIF
├── Cargo.toml                          # workspace
├── Cargo.lock
├── rust-toolchain.toml
├── rustfmt.toml
├── clippy.toml
├── deny.toml
├── cliff.toml
├── .editorconfig
├── .gitignore
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── LICENSE-MIT
└── LICENSE-APACHE
```

---

## 5. Git and GitHub workflow

### 5.1 Branching
- Trunk-based: `main` is always releasable and protected.
- Branch names: `<type>/<short-kebab-description>`, e.g. `feat/core-kdf`, `fix/header-length-check`, `docs/threat-model`, `test/tamper-suite`, `ci/coverage`, `chore/bootstrap`.
- One branch per issue. Delete after merge.

### 5.2 Commits — Conventional Commits
Format: `<type>(<scope>): <imperative summary>` — summary ≤ 72 chars, lowercase after the colon, no trailing period. Body explains **why** when not obvious. Footer references the issue.

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `ci`, `build`, `chore`, `security`.
Scopes: `core`, `kdf`, `crypto`, `header`, `storage`, `gen`, `cli`, `clipboard`, `ci`, `deps`, `docs`, `release`.

```
feat(kdf): derive 256-bit key with argon2id

Wraps argon2::Argon2 with explicit params rather than defaults so the
values written to the header are exactly the values used.

Refs #4
```

Rules:
- **Each commit compiles and passes tests.** No "wip" or "fix typo" commits on `main` — squash those on your branch before merge with an interactive rebase.
- Aim for **3–8 commits per PR**, each a coherent step (e.g. "add type", "implement", "add tests", "document").
- Breaking changes to the file format use `feat!:` and a `BREAKING CHANGE:` footer.
- Commits are authored under the repository owner's configured git identity. Sign commits if the owner has set up signing (`git config commit.gpgsign true`); never configure signing keys yourself.

### 5.3 Pull requests
- Title in Conventional Commit form (it becomes the release-notes line).
- Body follows the PR template (Section 6.3) and includes `Closes #<issue>`.
- Apply one `type:` label, one `area:` label, and the milestone.
- Keep PRs under ~400 changed lines (excluding lockfile and generated files). Split if larger.
- Merge only when CI is green, the template checklist is complete, and any 🛑 checkpoint has been answered.
- **Merge method: rebase-and-merge**, keeping linear history with each meaningful commit visible on `main`.

### 5.4 The agent's loop for every PR
```bash
git switch main && git pull --ff-only
gh issue create --title "feat(kdf): argon2id key derivation" \
  --body-file /tmp/issue.md --label "type: feature,area: crypto" --milestone "v0.1 — Crypto core"
git switch -c feat/core-kdf

# ...implement in small commits...
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check

git push -u origin feat/core-kdf
gh pr create --fill-first --body-file /tmp/pr.md \
  --label "type: feature,area: crypto" --milestone "v0.1 — Crypto core"
gh pr checks --watch
gh pr diff                       # self-review the full diff against Section 9
gh pr comment --body "Self-review: <what you checked, anything left for the owner>"
gh pr merge --rebase --delete-branch
```

If CI fails: fix with new commits on the branch, push, re-watch. Never merge red. Never disable a check to get green.

### 5.5 Labels
```bash
for l in "type: feature:0e8a16" "type: bug:d73a4a" "type: docs:0075ca" "type: test:fbca04" \
         "type: chore:cfd3d7" "type: security:b60205" \
         "area: crypto:5319e7" "area: format:5319e7" "area: cli:1d76db" "area: storage:1d76db" \
         "area: ci:bfdadc" "question:d876e3" "good first issue:7057ff"; do
  gh label create "${l%:*}" --color "${l##*:}" --force
done
```

### 5.6 Milestones
```bash
for m in "v0.0 — Repository setup" "v0.1 — Crypto core" "v0.5 — Feature complete" \
         "v1.0 — Release" "v1.x — Stretch goals"; do
  gh api repos/{owner}/{repo}/milestones -f title="$m"
done
```

### 5.7 Repository settings and branch protection
Run once, after the first CI run on `main` has registered its check names:
```bash
gh repo edit --enable-rebase-merge --enable-squash-merge=false --enable-merge-commit=false \
  --delete-branch-on-merge --enable-issues --enable-wiki=false

gh api -X PUT repos/{owner}/{repo}/branches/main/protection \
  -H "Accept: application/vnd.github+json" --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["test (ubuntu-latest)", "test (macos-latest)", "test (windows-latest)", "supply-chain"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```
- Review approval is **not** required because this is a solo repository (a required review would block every merge). Status checks are required.
- Branch protection on private repositories needs a paid GitHub plan; keep the repo public or tell the owner.
- Enable **Dependabot alerts**, **secret scanning** and **private vulnerability reporting** in Settings → Code security (ask the owner if the API call is refused).

---

## 6. Files to create in Milestone v0.0

### 6.1 `.github/workflows/ci.yml`
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -D warnings

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4          # Dependabot keeps actions current
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings
      - run: cargo test --workspace --all-features
      - name: Release build excludes test-only features
        run: cargo build --release -p pwv-cli

  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```
Added later: a `coverage` job (PR #21) and a short `fuzz` smoke job on nightly (PR #20). If the Linux job fails to build `arboard` for missing system libraries, install them in a step guarded by `if: runner.os == 'Linux'`; unit tests must not touch the real clipboard (Section 8, PR #18).

### 6.2 `.github/dependabot.yml`
```yaml
version: 2
updates:
  - package-ecosystem: cargo
    directory: /
    schedule: { interval: weekly }
    groups:
      rust-deps: { patterns: ["*"] }
    commit-message: { prefix: "build(deps)" }
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
    commit-message: { prefix: "ci(deps)" }
```

### 6.3 `.github/pull_request_template.md`
```markdown
## Summary
<!-- What changed and why, in 2–4 sentences. -->

Closes #

## Type of change
- [ ] feat  - [ ] fix  - [ ] docs  - [ ] test  - [ ] refactor  - [ ] ci/chore  - [ ] security

## How was this tested?
<!-- Commands run, new tests added, manual checks. -->

## Security checklist
- [ ] No secret in args, env vars, logs, Debug output, errors or panics
- [ ] Crypto is called only from `pwv-core::kdf` / `pwv-core::crypto`
- [ ] Any new header/file-format field is inside the AAD and validated on load
- [ ] Failure paths have tests (wrong password, tampering, bad input)
- [ ] Docs (README / DESIGN / THREAT_MODEL) updated if behaviour changed

## Notes for the reviewer
```

### 6.4 Issue forms
- `bug_report.yml`: fields for version (`pwv --version`), OS, steps to reproduce, expected vs actual, and a required checkbox "I have removed any real passwords from this report".
- `feature_request.yml`: problem, proposed solution, alternatives, security impact.
- `config.yml`: `blank_issues_enabled: false` and a contact link pointing security reports to `SECURITY.md` / private vulnerability reporting.

### 6.5 Other community files
- `CODEOWNERS`: `* @<owner>`
- `SECURITY.md`: supported versions table, how to report privately (GitHub private vulnerability reporting), expected response time, and the statement "This is an educational project and has not been independently audited."
- `CONTRIBUTING.md`: setup, the commands from 5.4, commit convention, branch naming, PR rules.
- `CODE_OF_CONDUCT.md`: Contributor Covenant 2.1.
- `LICENSE-MIT` + `LICENSE-APACHE` (dual licence, the Rust ecosystem norm).

### 6.6 Tooling config
- `rust-toolchain.toml`: `channel = "stable"`, `components = ["rustfmt", "clippy"]`.
- Workspace `Cargo.toml`: `resolver = "2"`, `[workspace.package]` with `edition = "2021"` (or the current edition), `rust-version`, `license = "MIT OR Apache-2.0"`, `repository`; `[workspace.lints.rust] unsafe_code = "forbid"`; `[workspace.lints.clippy] all = "warn"` plus `unwrap_used = "warn"` in non-test code.
- `[profile.release]`: `lto = true`, `codegen-units = 1`, `strip = true`, `panic = "abort"`.
- `deny.toml` (start from `cargo deny init`, then):
  ```toml
  [graph]
  all-features = true

  [advisories]
  version = 2
  yanked = "deny"

  [licenses]
  version = 2
  allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib", "CC0-1.0"]

  [bans]
  multiple-versions = "warn"

  [sources]
  unknown-registry = "deny"
  unknown-git = "deny"
  ```
  If `cargo deny` reports a schema change, follow its message rather than this snippet.
- `cliff.toml`: from `git cliff --init`, grouping commits by type.
- `.gitignore`: `/target`, `*.pwv`, `*.pwv.bak`, `.env`, `/fuzz/artifacts`, `/fuzz/corpus`, `.DS_Store`.

---

## 7. Shared engineering requirements

### Secret handling
- Master password: `secrecy::SecretString` from prompt to KDF; never cloned into a plain `String`.
- Derived key: `Zeroizing<[u8; 32]>`.
- Decrypted plaintext buffer: `Zeroizing<Vec<u8>>`. `Entry.password` uses a wrapper type whose `Debug` prints `"<redacted>"` and that zeroizes on drop.
- `Vault` and `Entry` implement `Debug` manually (or via a redacting wrapper) — never `#[derive(Debug)]` on a struct holding a secret.
- README states the limits: copies made by `serde_json`, the terminal, the clipboard and the OS cannot all be wiped.

### Testability
- `pwv-core` has no I/O except in `storage.rs`; everything else is pure and unit-testable.
- The clipboard is behind a `Clipboard` trait with `ArboardClipboard` and an in-memory `FakeClipboard` for tests.
- Time is injectable where it matters (`created_at`/`updated_at`, clipboard timeout) so tests don't sleep 30 s.
- Fast KDF for tests: cargo feature `insecure-test-kdf` lowers the default and the floor. It is **off by default**, and a test asserts that `KdfParams::default()` meets the production floor when the feature is off.

---

## 8. Milestones and pull requests

Each PR lists: **Branch** · **Commits** (suggested) · **Acceptance criteria**. Create the issue first, then the branch.

### Milestone v0.0 — Repository setup

**Initial commit (directly on `main`, the only direct push ever):** `chore: initial commit` with `README.md` stub (name, one-line description, "work in progress"), licences, `.gitignore`. Create the GitHub repo with `gh repo create <owner>/keyward --public --source . --push`. (Decision: the repository is named `keyward`; crates and the binary keep the `pwv` names.)

**PR #1 — `chore: bootstrap cargo workspace and ci`**
- Branch: `chore/bootstrap`
- Commits:
  1. `build: add cargo workspace with pwv-core and pwv-cli crates`
  2. `build: add toolchain, rustfmt, clippy and editorconfig settings`
  3. `ci: add fmt, clippy and test workflow on three platforms`
  4. `test(core): add placeholder test so ci has something to run`
- Accept: CI green on all three OSes. Then run Sections 5.5–5.7 (labels, milestones, protection).

**PR #2 — `docs: add design document and threat model draft`**
- Branch: `docs/design`
- Commits:
  1. `docs: add DESIGN.md with goals and non-goals`
  2. `docs: specify vault file format v1`
  3. `docs: add threat model draft`
  4. `docs: add ADR 0001 choosing xchacha20-poly1305 over aes-gcm`
- Accept: `DESIGN.md` contains the Section 2 format table, KDF profile table and error policy; `THREAT_MODEL.md` contains assets, adversaries, in/out of scope, assumptions.
- 🛑 **HUMAN CHECKPOINT:** owner reviews and approves the format and threat model before any crypto code is written.

**PR #3 — `chore: add community files, templates and supply-chain checks`**
- Branch: `chore/community-files`
- Commits:
  1. `docs: add contributing guide, security policy and code of conduct`
  2. `chore: add issue forms and pull request template`
  3. `ci: add dependabot and codeowners`
  4. `ci: add cargo-deny job`
- Accept: `supply-chain` job green; issue forms render on GitHub.

### Milestone v0.1 — Crypto core

**PR #4 — `feat(kdf): argon2id key derivation`**
- Branch: `feat/core-kdf`
- Commits:
  1. `feat(kdf): add KdfParams with default, floor and ceiling`
  2. `feat(kdf): derive 256-bit key with argon2id`
  3. `test(kdf): add rfc 9106 known-answer test`
  4. `test(kdf): reject params outside floor and ceiling`
- Accept: `derive_key(&SecretString, &[u8;16], &KdfParams) -> Result<Zeroizing<[u8;32]>>`; KAT passes (RFC 9106 §5.3 Argon2id vector, using the crate's secret/associated-data support, or the crate's own published vectors if unavailable — document which); out-of-range params return `ParamsOutOfRange`.

**PR #5 — `feat(header): encode and parse vault header`**
- Branch: `feat/core-header`
- Commits:
  1. `feat(header): define Header struct and constants`
  2. `feat(header): encode header to 59 bytes`
  3. `feat(header): parse header with strict validation`
  4. `test(header): cover bad magic, version, ids, lengths and params`
- Accept: `Header::to_bytes() -> [u8; HEADER_LEN]`, `Header::parse(&[u8]) -> Result<(Header, &[u8])>`; round-trip test; every malformed case returns a typed error, never panics.

**PR #6 — `feat(crypto): seal and open with header as associated data`**
- Branch: `feat/core-aead`
- Commits:
  1. `feat(crypto): seal plaintext with xchacha20-poly1305`
  2. `feat(crypto): open ciphertext and map failures to generic error`
  3. `test(crypto): add xchacha20-poly1305 known-answer test`
  4. `test(crypto): changing any header byte fails decryption`
- Accept: `seal(key, &Header, plaintext) -> Vec<u8>` (fresh random nonce written into the header), `open(key, file_bytes) -> Result<Zeroizing<Vec<u8>>>`; KAT from draft-irtf-cfrg-xchacha (Appendix A.3.1) passes; error message is exactly "wrong password or corrupted vault".
- 🛑 **HUMAN CHECKPOINT:** owner reviews #4–#6 together before merge of #6. Post a comment explaining nonce generation, AAD coverage and parameter validation in plain language.

**PR #7 — `feat(core): vault and entry data model`**
- Branch: `feat/core-model`
- Commits:
  1. `feat(core): add Vault and Entry types with serde`
  2. `feat(core): add redacting secret wrapper for passwords`
  3. `feat(core): add find, insert, update and remove operations`
  4. `test(core): debug output never contains password text`
- Accept: entries keyed by UUID; `find(site)` returns all matches; `Debug` redaction test.

**PR #8 — `feat(storage): atomic vault persistence`**
- Branch: `feat/core-storage`
- Commits:
  1. `feat(storage): resolve default vault path`
  2. `feat(storage): create vault from master password`
  3. `feat(storage): unlock and save with atomic rename`
  4. `feat(storage): keep previous file as .bak and set 0600 on unix`
  5. `test(storage): failure before rename leaves original intact`
- Accept: `create(path, password)`, `unlock(path, password) -> UnlockedVault`, `UnlockedVault::save()` — temp file in same directory → `sync_all` → rename; salt kept, nonce fresh on each save.

**PR #9 — `test(core): tamper, truncation, downgrade and property tests`**
- Branch: `test/core-security-suite`
- Commits:
  1. `test(core): flipping every byte of a small vault is rejected`
  2. `test(core): truncated, empty and extended files are rejected`
  3. `test(core): header downgrade of memory cost is rejected`
  4. `test(core): property test that random vaults round-trip`
  5. `test(core): two saves produce different nonces and ciphertexts`
  6. `test(core): wrong password fails and leaves file unchanged`
- Accept: all pass; each test's doc comment names the README claim it proves.

**PR #10 — `perf(kdf): benchmark and calibrate default parameters`**
- Branch: `perf/kdf-calibration`
- Commits:
  1. `perf(kdf): add kdf timing example binary`
  2. `docs: record benchmark results and chosen defaults`
- Accept: `cargo run --release --example kdf_bench` prints timings for several profiles; `DESIGN.md` records the owner's machine result and the chosen default (target 0.5–1 s unlock). Ask the owner to run it on their laptop and paste results if the agent's environment differs.

**Release v0.1.0** (Section 10).

### Milestone v0.5 — Feature complete

**PR #11 — `feat(cli): command-line scaffold`**
- Branch: `feat/cli-scaffold`
- Commits: `feat(cli): define commands and global flags with clap` · `feat(cli): map errors to exit codes` · `feat(cli): add hidden password prompt and --password-stdin` · `test(cli): help and version output`
- Accept: `pwv --help` lists all commands; exit codes per Section 2; `--password-stdin` documented as automation-only in help text.

**PR #12 — `feat(cli): init command`**
- Branch: `feat/cli-init`
- Commits: `feat(cli): implement init with double prompt` · `feat(cli): reject weak master passwords using zxcvbn` · `feat(cli): refuse to overwrite without --force` · `test(cli): init creates a valid vault`
- Accept: minimum length 12 and zxcvbn score ≥ 3 (explain feedback to user without echoing the password).

**PR #13 — `feat(cli): add and list commands`**
- Branch: `feat/cli-add-list`
- Accept: `add` prompts for every secret field; `list` prints a table of site + username only; `--search` is case-insensitive substring.

**PR #14 — `feat(cli): get, edit and delete commands`**
- Branch: `feat/cli-get-edit-delete`
- Accept: ambiguity prompt for multiple matches; `--show` refuses when stdout is not a TTY unless `--force`; `delete` confirms; `updated_at` bumps on edit. `get` prints to stdout only with `--show` (clipboard comes in PR #18).

**PR #15 — `feat(cli): change-master command`**
- Branch: `feat/cli-change-master`
- Accept: old password required; new salt generated; old password no longer opens the vault (test); `.bak` updated.

**PR #16 — `feat(gen): secure password and passphrase generator`**
- Branch: `feat/core-generator`
- Commits: `feat(gen): generate passwords from selected character classes` · `feat(gen): guarantee each class via rejection sampling` · `feat(gen): add eff wordlist passphrases` · `feat(gen): report estimated entropy` · `test(gen): length, classes and chi-squared distribution`
- Accept: OsRng only; unbiased selection via the `rand` crate's uniform choose (no `%`); default length 20, min 8, max 256; ambiguous set `0 O 1 l I`; chi-squared test over ≥ 1 000 000 characters passes at p > 0.001; wordlist attribution added to README.

**PR #17 — `feat(cli): gen command and add --generate`**
- Branch: `feat/cli-gen`
- Accept: `pwv gen` prints password + entropy (entropy to stderr so piping stays clean); `add --generate` accepts the same options.

**PR #18 — `feat(clipboard): copy with automatic clearing`**
- Branch: `feat/cli-clipboard`
- Commits: `feat(clipboard): add Clipboard trait with arboard and fake implementations` · `feat(clipboard): clear after timeout only if content unchanged` · `feat(clipboard): clear immediately on ctrl-c` · `feat(clipboard): exclude from clipboard history where supported` · `test(clipboard): clearing logic with fake clipboard and injected clock`
- Accept: `get` copies by default; foreground countdown on stderr; compares a SHA-256 hash of the copied value (not the value) before clearing; uses `arboard`'s platform extension to exclude from history where available (check docs.rs) — otherwise documented as a limitation; no test touches the real clipboard.

**PR #19 — `test(cli): end-to-end integration tests`**
- Branch: `test/cli-e2e`
- Accept: `assert_cmd` drives the real binary in a temp dir with `--vault` and `--password-stdin` under `insecure-test-kdf`: init → add → list → get --show → edit → delete → change-master; wrong password exits 3; tampered file exits 3; no test output contains the test passwords except where `--show` is the point.

**Release v0.5.0.**

### Milestone v1.0 — Release

**PR #20 — `test: fuzz header parser`**
- Branch: `test/fuzz-header`
- Accept: `fuzz/fuzz_targets/parse_header.rs`; CI `fuzz` job on nightly runs it for 60 s on PRs touching `header.rs` (path filter) and never fails the build for timeouts — only for crashes.

**PR #21 — `ci: coverage reporting`**
- Branch: `ci/coverage`
- Accept: `cargo llvm-cov` job uploads an lcov report as an artifact (or to Codecov if the owner provides a token — never ask for or store tokens yourself); README badge; ≥ 90% line coverage on `kdf`, `header`, `crypto`, `storage`.

**PR #22 — `security: runtime hardening`**
- Branch: `security/hardening`
- Accept: warn if vault is group/world-readable on Unix; disable core dumps on Unix at startup (`setrlimit` via the `rlimit` crate) — optional, document if skipped; optional plaintext padding to a 1 KiB multiple to blur entry count (if added: bump nothing in the header, padding is inside the ciphertext; document it in `DESIGN.md`).

**PR #23 — `docs: complete readme and threat model`**
- Branch: `docs/v1-readme`
- README sections, in order:
  1. Name, one-line pitch, badges (CI, coverage, licence), demo GIF
  2. ⚠️ "Educational project — not independently audited"
  3. Features
  4. Install (`cargo install`, release binaries)
  5. Quick start
  6. Command reference
  7. Cryptographic design (link `DESIGN.md`), with the file-format table
  8. Threat model summary (link `THREAT_MODEL.md`), each claim linked to the test that proves it
  9. Testing (how to run; what is covered)
  10. Limitations
  11. Development process (built with AI-agent assistance; design and review by the owner)
  12. Acknowledgements (EFF wordlist, libraries) · Licence
- `THREAT_MODEL.md` final: assets; adversaries (file theft, file tampering, header downgrade, rollback to older valid vault, shoulder-surfing, clipboard readers, metadata observers, local malware, root/OS compromise); in/out of scope with mitigations; assumptions; known limitations (rollback undetectable, clipboard history, memory copies, metadata).
- `docs/demo.tape` (Charm VHS) recording: init → add --generate → list → get (countdown) → corrupt one byte with a hex one-liner → get fails with exit 3. Commit the generated GIF under `docs/`.
- 🛑 **HUMAN CHECKPOINT:** owner reads README and threat model end to end before merge.

**PR #24 — `chore(release): release automation`**
- Branch: `chore/release-automation`
- Accept: cargo-dist initialised (its init command, `dist init` in current versions) for Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64, with checksums; `cliff.toml` generates `CHANGELOG.md`; `CONTRIBUTING.md` documents the release steps.

**Release v1.0.0.** 🛑 **HUMAN CHECKPOINT** before pushing the tag.

### Milestone v1.x — Stretch goals (one PR each, in this order)

| PR | Title | Key acceptance criteria |
| --- | --- | --- |
| #25 | `feat(audit): breach check with pwned passwords range api` | Opt-in `pwv audit`; SHA-1 locally, send only 5-char prefix to `https://api.pwnedpasswords.com/range/{prefix}` with `Add-Padding: true` and a descriptive `User-Agent`; ignore count-0 padding rows; network failure is reported as "unknown", never "safe"; tests use a mocked HTTP layer; threat model updated (the only network feature). |
| #26 | `feat(totp): store secrets and print codes` | Base32 secret per entry; parse `otpauth://` URIs; `pwv otp <site>` shows code + seconds left; RFC 6238 Appendix B vectors pass; threat model notes that TOTP in the same vault merges two factors. |
| #27 | `feat(import): csv import from browsers` | `pwv import --format chrome|firefox <file>`; header-row detection; `--dry-run`; de-duplication; never logs rows; warns user to delete the plaintext CSV. |
| #28 | `feat(tui): interactive terminal ui with auto-lock` | `pwv tui` with `ratatui`; search, detail, copy; key held in memory, wiped after N minutes idle (default 5) and on exit; threat model updated for the long-lived key. |
| #29 | `feat(gui): tauri desktop app` | New `crates/pwv-gui`; reuses `pwv-core`; narrow Tauri commands (unlock, list, copy) — never send the full decrypted vault to the webview; strict CSP; Tauri capability/permission config minimal. 🛑 checkpoint on the IPC design. |

Tag `v1.1.0`, `v1.2.0`, … as each lands.

---

## 9. Definition of done (every PR)

- [ ] Issue exists and is linked with `Closes #N`
- [ ] Branch follows naming rule; commits follow Conventional Commits and each compiles
- [ ] `cargo fmt`, `clippy -D warnings`, `cargo test --workspace --all-features`, `cargo deny check` pass locally and in CI
- [ ] New behaviour has tests, including failure paths
- [ ] Security checklist in the PR template is fully ticked
- [ ] Docs updated (README / DESIGN / THREAT_MODEL / CHANGELOG via commit messages)
- [ ] Self-review comment posted after reading `gh pr diff`
- [ ] Labels and milestone set
- [ ] Any 🛑 checkpoint answered by the owner

## 10. Security invariants (verify before every release)

- [ ] Fresh random nonce on every save; salt changes only on init/change-master
- [ ] Entire 59-byte header is AAD
- [ ] KDF params validated against floor and ceiling on every load
- [ ] Single generic decryption error; no added timing or message differences
- [ ] OS CSPRNG only; unbiased selection
- [ ] No secrets in args, env, logs, `Debug`, errors, panics, test output
- [ ] Atomic writes, `.bak` kept, `0600` permissions
- [ ] Clipboard cleared after timeout only if unchanged
- [ ] `insecure-test-kdf` absent from default features and release builds
- [ ] `cargo deny check` clean; dependency versions listed in README
- [ ] Rollback, metadata and clipboard-history limits documented

## 11. Release process

```bash
git switch main && git pull --ff-only
# bump version in workspace Cargo.toml via a PR: "chore(release): prepare v0.1.0"
git cliff --tag v0.1.0 -o CHANGELOG.md     # included in that same PR
# after the PR merges:
git tag -a v0.1.0 -m "v0.1.0 — crypto core"
git push origin v0.1.0
```
- Before cargo-dist exists (v0.1, v0.5): create the GitHub release with `gh release create v0.1.0 --notes-file <section of CHANGELOG>`.
- From v1.0: pushing the tag triggers `release.yml`; verify the release page lists all binaries and checksums.
- Semantic Versioning: file-format changes that old versions can't read are a **major** bump (after 1.0) and must include a migration path.

## 12. Things the agent must not do

- Push directly to `main` after the initial commit, or force-push it
- Merge with failing or skipped checks, or weaken a check/lint to pass
- Change the file format, KDF parameters or cipher without a 🛑 checkpoint and an ADR
- Add network access outside the opt-in `audit` command
- Add telemetry, analytics or crash reporting
- Store, request or print tokens, API keys or the owner's credentials
- Backdate commits or fabricate history, reviews or contributors
- Copy code from other password managers without licence compatibility and attribution

---

## Appendix A — Swapping the language

If the owner chooses Go or Python instead, keep Sections 0, 1, 2, 5, 8–12 unchanged (rename crates to packages) and replace Sections 3, 4, 6.1 and 6.6:

| Concern | Go | Python |
| --- | --- | --- |
| KDF / AEAD | `golang.org/x/crypto/argon2` `IDKey`; `x/crypto/chacha20poly1305` `NewX` | `argon2-cffi` `low_level.hash_secret_raw`; `PyNaCl` XChaCha20-Poly1305 bindings |
| CLI / prompt | `cobra`; `golang.org/x/term` | `typer` (with `pretty_exceptions_show_locals=False`); `getpass` |
| Clipboard | `atotto/clipboard` | `pyperclip` |
| Tests / fuzz | `testing`, `go test -fuzz` | `pytest`, `hypothesis` |
| Lint / audit | `go vet`, `staticcheck`, `govulncheck` | `ruff`, `bandit`, `pip-audit`, `mypy --strict` |
| CI setup action | `actions/setup-go` | `astral-sh/setup-uv` |
| Releases | `goreleaser` | build with `uv build`, publish via PyPI trusted publishing |
| Memory hygiene | `awnumar/memguard` | documented limitation |