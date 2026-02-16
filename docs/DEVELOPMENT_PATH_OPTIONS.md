# Development Path Options

Last updated: February 16, 2026

## Goal

Provide clear choices for how to continue development on the fork, including environment setup strategy.

## Path A: Upstream-First Integration

Best when long-term maintainability and low drift are top priorities.

Workflow:

1. Merge `upstream/main` weekly (or per milestone).
2. Keep fork features behind small, isolated commits.
3. Resolve conflicts early while context is fresh.
4. Run container compile after every sync.

Pros:

- smaller future merge conflicts
- easier upstream contribution and cherry-pick strategy
- better compatibility with upstream fixes/security patches

Cons:

- slightly slower feature velocity during frequent sync windows

## Path B: Fork-Product-First

Best when feature velocity and product differentiation are top priorities.

Workflow:

1. Build fork features quickly on fork branches.
2. Sync upstream less frequently (for example once per release cycle).
3. Dedicate an explicit "sync sprint" for conflict resolution.

Pros:

- fastest short-term feature throughput
- clearer focus on fork-specific roadmap

Cons:

- larger, riskier merge batches later
- higher integration cost and test burden during sync

## Path C: Stabilize-Then-Scale

Best when you want one hardening cycle before choosing A or B permanently.

Workflow:

1. Freeze major new features temporarily.
2. Close merge regressions, tighten test coverage, clean config/docs.
3. Establish baseline CI and container checks.
4. Choose Path A or B with known risk profile.

Pros:

- reduces hidden technical risk
- creates clean base for later velocity

Cons:

- short-term slowdown in feature output

## Development Environment Options

### Option 1: Container-Only (Recommended default)

Use when onboarding contributors quickly and avoiding local toolchain drift.

Commands:

```bash
docker build -t picoclaw:dev .
docker run --rm picoclaw:dev version
```

Pros:

- reproducible builds
- no local Go required

Cons:

- slower inner loop than native builds

### Option 2: Hybrid (Local Go + Container)

Use local Go for fast iteration, container for release parity checks.

Commands:

```bash
make build
go test ./...
docker build -t picoclaw:dev .
```

Pros:

- fastest coding loop
- still keeps release-grade container verification

Cons:

- requires local Go toolchain setup consistency

### Option 3: Containerized Go Run (No local install, interactive)

Run Go build/test commands inside a disposable Go container with source mounted.

```bash
docker run --rm -it -v "$PWD":/src -w /src golang:1.26-alpine sh -lc \
'apk add --no-cache git make && make build && ./build/picoclaw version'
```

Pros:

- no host Go install
- closer to CI/runtime consistency

Cons:

- still slower than native local Go

## Decision Guide

If your next 4-8 weeks prioritize:

- stability and upstream compatibility: choose Path A + Environment Option 1 or 2
- rapid fork-specific feature delivery: choose Path B + Environment Option 2
- risk cleanup before acceleration: choose Path C + Environment Option 1, then move to A or B

## Suggested Immediate Baseline

If undecided, use this baseline now:

1. Adopt Path C for one short hardening pass (1-2 weeks).
2. Use Environment Option 1 for all CI/release checks.
3. Optionally use Environment Option 2 locally for faster coding.
4. Re-decide between Path A and B after hardening metrics are visible.
