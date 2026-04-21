## Summary

- What changed:
- Why:

## Validation

- [ ] `gofmt -w ./cmd ./internal`
- [ ] `go test ./...`
- [ ] `gitleaks git . --staged --no-banner`
- [ ] Updated docs or contracts if lab behavior or validation expectations changed

## Risk and Rollback

- Risk level: low / medium / high
- Rollback plan:

## Scope Check

- [ ] Focused, single-purpose change
- [ ] No secrets introduced
- [ ] Non-operator docs were kept out of the repo unless they are required for build, validation, release, install, or packaging
