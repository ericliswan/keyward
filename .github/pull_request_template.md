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
