# Contributing

Thanks for contributing to Anchor Protocol.

## Ground rules

- Keep protocol verification deterministic and offline-capable.
- Preserve backward compatibility unless the change is explicitly versioned as breaking.
- Include tests for every behavior change.
- Use clear commit messages (prefer conventional commits).

## Development setup

```bash
go test ./...
```

## Pull requests

1. Open an issue first for non-trivial changes.
2. Add or update tests and docs in the same PR.
3. Ensure CI is green.
4. Include migration notes when changing schemas, reason codes, or SDK behavior.

## Conformance-sensitive areas

Changes in these areas require extra care:

- `core/` canonicalization, hashing, signing, verification
- `spec/` schemas and reason-code registry
- `sdk/` behavior parity across language SDKs
- `conformance/` vectors and test harness

## Security issues

Do not open public issues for vulnerabilities. Follow `SECURITY.md`.
