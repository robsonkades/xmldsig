# Contributing to xmldsig

Thanks for your interest in contributing! This document explains how to build the project and what
is expected from a pull request.

## Prerequisites

- JDK 25
- Maven 3.9+

## Building and testing

```
mvn verify
```

The test suite signs and verifies real fiscal layouts (NF-e, NFC-e, CT-e, MDF-e, NFS-e and NF-e
events) under `src/test/resources/fiscal/`, using the throwaway certificate in
`src/test/resources/test-keystore.p12` (password `changeit`).

Every change must keep the suite green. Never weaken, disable or delete a test to make it pass —
if you believe a test is wrong, say so in the PR and explain why.

## Project layout notes

- `src/main/moditect/module-info.java` — the JPMS descriptor. It is **not** compiled by javac;
  [Moditect](https://github.com/moditect/moditect) injects it into the jar during `package`. This
  keeps the project non-modular for IDEs and Surefire, so the whitebox tests run on the classpath.
  If you change the public API surface or dependencies, update this file accordingly.
- `benchmarks/` — standalone JMH project, never published. If your change claims a performance
  impact, back it with numbers from these benchmarks (see the README for how to run them).

## Guidelines

- **Scope**: keep pull requests small and focused — one logical change per PR. Report unrelated
  bugs as issues instead of fixing them in passing.
- **Simplicity**: no speculative features, parameters or abstractions. The simplest solution that
  solves the problem wins.
- **Style**: follow the conventions of the surrounding code. Comments explain *why*, not *what*.
- **Compatibility**: the signature output is validated by SEFAZ — any change touching parsing,
  canonicalization or serialization must not alter signed bytes. The round-trip tests guard this;
  treat them as a contract.
- **Javadoc**: the public API is fully documented and builds without warnings
  (`mvn javadoc:javadoc`). Keep it that way.
- **Dependencies**: this library ships with a single runtime dependency (Apache Santuario).
  Adding a new one needs a very good reason — open an issue first.

## Commits

- Write commit messages in English, using the conventional prefixes already in the history
  (`feat:`, `fix:`, `docs:`, `build:`, `perf:`, `chore:`).
- Explain the *why* in the message body when it is not obvious from the diff.

## Submitting a pull request

1. Fork the repository and create a branch from `master`.
2. Make your change, including tests for new behavior.
3. Run `mvn verify` and make sure it passes.
4. Open the pull request with a clear description of the problem and the solution.

## License

By contributing you agree that your contributions are licensed under the
[Apache License, Version 2.0](LICENSE).
