# Contributing to cavos-account

Thank you for your interest in contributing! This guide covers everything you need to get started.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating you agree to uphold its terms.

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](../../issues/new?template=bug_report.md) with:
- A clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Scarb / snforge versions (`scarb --version`, `snforge --version`)

### Suggesting Features

Open a [GitHub Issue](../../issues/new?template=feature_request.md) with:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you considered

### Submitting a Pull Request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. Make your changes following the [style guide](#style-guide) below.

3. Add or update tests in `tests/`:
   ```bash
   snforge test
   ```
   All tests must pass.

4. Open a pull request against `main`. Fill in the PR template.

## Development Setup

```bash
# Install Scarb 2.14.0
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh -s -- --version 2.14.0

# Install starknet-foundry
curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh

# Build
scarb build

# Run all tests
snforge test

# Run a specific test
snforge test test_name
```

## Style Guide

- Follow Cairo edition `2024_07` idioms.
- Prefer `for x in span` over `while` + index loops.
- Use `DivRem::div_rem` for combined division + remainder operations.
- Cache `span.len()` before loops.
- Use `span.slice()` instead of building intermediate arrays.
- Keep functions short and single-purpose.
- Document public functions and structs with `///` doc comments.
- No `unwrap()` in production paths — handle errors explicitly.

## Testing

Tests live in `tests/`. Each test module covers a specific area:

| File | Coverage |
|------|----------|
| `test_math_regressions.cairo` | JWT parsing, crypto primitives, policy helpers |

Add tests for any new functionality. Regression tests are especially welcome for edge cases (overflow, empty input, boundary values).

## Security

If you discover a security vulnerability, **do not open a public issue**. Email the maintainers directly (see [SECURITY.md](SECURITY.md)).
