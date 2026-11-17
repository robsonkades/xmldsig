# Contributing to xmldsig

Thanks for your interest in contributing! This document explains how to build the project and what
is expected from a pull request.

## Prerequisites

- JDK 25 or newer
- The checked-in Maven Wrapper (Maven 3.9.15, download verified by SHA-256)

## Building and testing

```
sh ./mvnw clean verify
```

On Windows, run `.\mvnw.cmd clean verify`. The wrapper downloads Maven on first use.
CI and releases use Temurin 25.0.3+9 and Ubuntu 24.04. The compiler target remains Java 25;
local development may use another compatible JDK, but release recovery should use the recorded
toolchain. Maven lifecycle plugin versions are explicit in both POMs. Updating the Maven pin
also requires updating `distributionSha256Sum` in `.mvn/wrapper/maven-wrapper.properties`.
See the [Maven Wrapper checksum documentation](https://maven.apache.org/wrapper/#checksum-verification-of-downloaded-binaries).

Ordinary builds do not need GPG or publishing credentials. Signing and Central publishing are
enabled only by `-Prelease`.

The test suite signs and verifies small fiscal-layout fixtures (NF-e, NFC-e, CT-e, MDF-e, NFS-e
and NF-e events) under `src/test/resources/fiscal/`, using the throwaway certificate in
`src/test/resources/test-keystore.p12` (password `changeit`).
These fixtures do not prove full schema compliance or acceptance by a fiscal authorizer.

Every change must keep the suite green. Never weaken, disable or delete a test to make it pass —
if you believe a test is wrong, say so in the PR and explain why.

## Project layout notes

- `src/main/moditect/module-info.java` — the JPMS descriptor. It is **not** compiled by javac;
  [Moditect](https://github.com/moditect/moditect) injects it into the jar during `package`. This
  keeps the project non-modular for IDEs and Surefire, so the whitebox tests run on the classpath.
  CI also compiles and runs a separate JPMS consumer against the packaged artifact and its Maven
  dependencies. If you change the public API surface or dependencies, update this file accordingly.
- `benchmarks/` — standalone JMH project, never published. If your change claims a performance
  impact, back it with numbers from these benchmarks (see the README for how to run them).

## Guidelines

- **Scope**: keep pull requests small and focused — one logical change per PR. Report unrelated
  bugs as issues instead of fixing them in passing.
- **Simplicity**: no speculative features, parameters or abstractions. The simplest solution that
  solves the problem wins.
- **Style**: follow the conventions of the surrounding code. Comments explain *why*, not *what*.
- **Compatibility**: parsing, customization and namespace normalization happen before signing.
  After signing, serialization must preserve the signed XML's canonical value. Protect this with
  integrity and independent-verifier tests, including namespace and Unicode edge cases. Describe
  fiscal compatibility only for the layout/version and external evidence actually tested.
- **Javadoc**: the public API is fully documented and builds without warnings
  (`mvn javadoc:javadoc`). Keep it that way.
- **Dependencies**: keep the dependency graph small and inspect runtime transitive dependencies.
  Besides Santuario and JSpecify metadata, the POM supplies Jakarta XML Bind/Activation APIs for
  Santuario's JPMS requirements. Explain the reason for any new dependency in the pull request.

## Commits

- Write commit messages in English, using the conventional prefixes already in the history
  (`feat:`, `fix:`, `docs:`, `build:`, `perf:`, `chore:`).
- Explain the *why* in the message body when it is not obvious from the diff.

## Submitting a pull request

1. Fork the repository and create a branch from `master`.
2. Make your change, including tests for new behavior.
3. Run `sh ./mvnw clean verify` (or `.\mvnw.cmd clean verify`) and make sure it passes.
4. Open the pull request with a clear description of the problem and the solution.

## Releases and recovery

The manual Release workflow accepts only `master` or the exact `v<version>` tag selected for
recovery. Other refs are rejected at job selection; an offline CLI check repeats the policy
before importing the signing key. The job references the GitHub environment named `release`.
Before using it, configure that environment in repository settings: allow the `master` branch
and release tags matching `v*`, select the required reviewers, and store the four publication
secrets there. The workflow's exact-version check is narrower than the environment's tag glob.
Declaring an environment in YAML does not create reviewer or branch protections; those settings
must be configured separately. See [GitHub deployment protections](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

The workflow validates the selected version, builds/tests/signs locally, captures
the signed POM and three JARs in `target/verified-release`, then pushes the release commit and tag
atomically. A SHA-256 manifest detects changes to those files or their detached signatures.
Central receives a bundle made from the captured bytes, and GitHub Release uses those same JARs;
publication never reruns the Maven lifecycle. It waits for Central publication before creating
the GitHub Release. Only this workflow activates `-Prelease` and needs publishing secrets.
Release Actions are pinned by commit, the release job does not restore a Maven cache, and its
summary records the runner image, JDK, Maven, release commit and artifact hashes. Both workflows
use the checked-in wrapper and exact JDK version. The `ubuntu-24.04` hosted image still receives
GitHub updates; its recorded image revision is evidence, not an immutable runner pin.

To resume a failed run, rerun the original workflow or select its existing release tag with the
same version. The selected source tree, after applying that version, must match the tag exactly;
the workflow never moves an existing tag. An already published version is reused only when its
POM and all three JARs match the rebuilt artifacts. A fixed timestamp from the release commit
makes the archive timestamps reproducible; use the recorded toolchain when investigating any
remaining byte differences. If Central is still processing a previous attempt or its
repository has not propagated the files yet, a repository HTTP 404 does not establish that
another upload is safe. The workflow stops by default when that tag already exists.

- Set `deployment_id` to the UUID from the previous release log or Central Portal to check its
  status through the [official Publisher API](https://central.sonatype.org/publish/publish-portal-api/#verify-status-of-the-deployment).
  `PENDING`, `VALIDATING` and `PUBLISHING` stop with instructions to resume later. `VALIDATED`
  requires publication in the Portal. `FAILED` requires reviewing its errors. Even `PUBLISHED`
  waits for the public artifacts to become visible and match the rebuilt release. None of these
  status checks performs a new upload or deletes/publishes an existing deployment.
- If the earlier run failed before uploading, or its deployment failed terminally, confirm in
  the Portal that no deployment of this version is active or published. Only then select
  `retry_upload=true` with no `deployment_id` to authorize a new upload. This is an explicit
  operator decision; the workflow cannot infer it from HTTP 404. The two recovery inputs cannot
  be combined.

HTTP requests have a 30-second timeout, do not follow redirects or automatically retry, and
do not log credentials or raw error bodies. New releases upload once through the
[Publisher API](https://central.sonatype.org/publish/publish-portal-api/) with automatic publication,
print the deployment ID immediately, and poll status for up to ten minutes (plus an in-flight
request). An upload or status failure stops with recovery guidance; it never replays an upload.
`--prepare` and `--check` on `scripts/release.py` operate offline and require the same `--version`
and `--timestamp` as the release. Preparation requires all four artifacts and their `.asc` files
from `mvn -Prelease clean verify`; it refuses to overwrite an existing snapshot.

Real publication and credentials are not exercised by ordinary CI. Both workflows run the
portable offline recovery tests using Python 3.10+ and its standard library:
`python3 -m unittest discover -s scripts/tests -v` (use your Python executable on Windows).
The tests mock HTTP, exercise bundle contents and hash checks, and never contact the Portal or
upload artifacts. Never commit production certificates, keystores, private keys or `.env` files;
the two explicitly allowed PKCS#12 fixtures are disposable test credentials.

## License

By contributing you agree that your contributions are licensed under the
[Apache License, Version 2.0](LICENSE).
