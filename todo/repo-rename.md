# Repo Rename: `AwsIO.jl` -> `Reseau.jl`

## Goal

Rename the `AwsIO` package/repo so the primary public API becomes `Reseau` (`using Reseau`) and update all downstream/local consumers (notably `AwsHTTP`, `HTTP`, `Postgres`, `Redis`, plus local dev environments) to use the new name.

This doc is a checklist/plan for doing the rename with minimal breakage and with a clear rollout order.

## Status (This Workspace)

- Date: 2026-02-07
- New package UUID: `802f3686-a58f-41ce-bb0c-3c43c75bba36`
- Old package UUID (AwsIO): `4047365c-aa37-44ec-b1fa-4c0d5495ccf1`
- Repo folder renamed:
  - Old: `/Users/jacob.quinn/.julia/dev/AwsIO`
  - New: `/Users/jacob.quinn/.julia/dev/Reseau`
- Branch used for rename: `reseau-rename`
- GitHub repo:
  - Created: `JuliaServices/Reseau.jl`
  - Remotes:
    - `origin`: `https://github.com/JuliaServices/Reseau.jl.git`
    - `awsio`: `https://github.com/JuliaServices/AwsIO.jl.git`
- Tests (all passing as run locally):
  - `Reseau` (this repo)
  - `AwsHTTP`
  - `HTTP`
  - `Postgres`
  - `Redis`
- Sanity checks:
  - `rg -n "\\bAwsIO\\b" /Users/jacob.quinn/.julia/dev -S -g'*.jl'` returns no matches.
  - `rg -n "AWSIO_" /Users/jacob.quinn/.julia/dev -S -g'*.jl'` returns no matches.

## Key Decisions (Resolve Early)

- [x] **UUID strategy:** mint a new UUID (treat as a new package identity).
- [x] **Compatibility strategy:** hard break (`using AwsIO` should fail; all consumers must update).
- [x] **Env var strategy:** rename `AWSIO_*` -> `RESEAU_*` (no compatibility aliases).
- [ ] **Registration strategy:** register as a new package in General vs. local-only for now.

Notes:
- Because the UUID changed, **every downstream `Project.toml` needed a UUID update**, not just a `[deps]` key rename.
- Because this is a hard break, there is intentionally **no** `AwsIO` shim/re-export package in this plan.

## Preflight / Safety

- [x] **Do the rename on a dedicated branch.** (Used: `reseau-rename`)
- [x] Baseline test run (before rename): `Pkg.test` passed.
- [x] Inventory *all* local usages: updated all `.jl` usages in `/Users/jacob.quinn/.julia/dev`.

## Rename Work Inside This Repo

### 1) Repo + Package Identity

- [x] Rename the repo directory (local) from `AwsIO` to `Reseau`.
- [x] Update `Project.toml`:
  - [x] `name = "Reseau"`
  - [x] `uuid = "802f3686-a58f-41ce-bb0c-3c43c75bba36"`
  - [x] Update `[extensions]` names: `ReseauS2NExt`

### 2) Module Entry Point

- [x] Rename `src/AwsIO.jl` -> `src/Reseau.jl`.
- [x] Rename `module AwsIO` -> `module Reseau`.
- [x] Update all internal references to the old module name.

### 3) Extensions

- [x] Rename the extension module/file:
  - [x] `ext/AwsIOS2NExt.jl` -> `ext/ReseauS2NExt.jl`
  - [x] `module AwsIOS2NExt` -> `module ReseauS2NExt`
  - [x] `using AwsIO` -> `using Reseau`
  - [x] Update `Project.toml [extensions]` accordingly.

### 4) Tests

- [x] Update `test/runtests.jl`: `using Reseau`.
- [x] Update `AwsIO.` qualified references in tests -> `Reseau.`.
- [x] Rename env vars (hard break, no aliases):
  - [x] `AWSIO_RUN_TLS_TESTS` -> `RESEAU_RUN_TLS_TESTS`
  - [x] `AWSIO_RUN_NETWORK_TESTS` -> `RESEAU_RUN_NETWORK_TESTS`
  - [x] `AWSIO_USE_SECITEM` -> `RESEAU_USE_SECITEM`

### 5) Docs + Repo Metadata

- [x] Update `README.md`:
  - [x] Title and `Pkg.add("Reseau")` / `using Reseau` examples.
  - [x] Badges/links updated to `JuliaServices/Reseau.jl`.
- [x] Update `AGENTS.md` references (repo name, downstream instructions, grep patterns).

### 6) Verify

- [x] Run `Pkg.test` after the rename.
- [x] Smoke import:

```sh
cd "$(git rev-parse --show-toplevel)"
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Reseau; println(Reseau)'
```

## Update Downstream Packages

General rule: this is both a **dependency rename** and a **namespace rename**.

- Dependency rename:
  - Update `[deps]` entry key from `AwsIO` to `Reseau` and update the UUID.
  - Update `[compat] AwsIO = ...` -> `[compat] Reseau = ...` (if present).

- Namespace rename:
  - Update `using AwsIO` -> `using Reseau`.
  - Update all `AwsIO.` qualifiers.
  - Update method extensions like `function AwsIO.somefunc(...)` -> `function Reseau.somefunc(...)`.

### AwsHTTP (`/Users/jacob.quinn/.julia/dev/AwsHTTP`)

- [x] Update `Project.toml` `[deps]` and `[compat]`.
- [x] Update `src/` and `test/` references.
- [x] Run tests (passed).

### HTTP (`/Users/jacob.quinn/.julia/dev/HTTP`)

- [x] Update `Project.toml` `[deps]` and `[compat]`.
- [x] Update `src/` and `test/` references.
- [x] Update local scratch scripts (`tmp_*.jl`) to use `Reseau`.
- [x] Run tests (passed).

### Postgres (`/Users/jacob.quinn/.julia/dev/Postgres`)

- [x] Update `Project.toml` `[deps]` and `[compat]`.
- [x] Update `using AwsIO` -> `using Reseau` in `src/`.
- [x] Update `Manifest-v1.12.toml` path dependency from `.../AwsIO` -> `.../Reseau`.
- [x] Run tests (passed).

### Redis (`/Users/jacob.quinn/.julia/dev/Redis`)

- [x] Update `Project.toml` `[deps]`.
- [x] Update `src/Redis.jl` imports and `Reseau.` qualifiers.
- [x] Remove invalid shared-manifest pointer (`manifest = "../Manifest.toml"`) and add:

```toml
[sources]
Reseau = {path = "/Users/jacob.quinn/.julia/dev/Reseau"}
```

- [x] Run tests (passed; generates `Redis/Manifest.toml`).

### Any Other Local Consumers

- [x] Final global search for `AwsIO` in `/Users/jacob.quinn/.julia/dev` (no `.jl` matches remain).

## Update Local Julia Environments

### `/Users/jacob.quinn/.julia/dev/Project.toml`

- [x] Rename `[deps] AwsIO = ...` -> `[deps] Reseau = ...` (new UUID).
- [x] Rename `[sources] AwsIO = {path = ".../AwsIO"}` -> `[sources] Reseau = {path = ".../Reseau"}`.
- [x] Run `Pkg.resolve()` and `Pkg.instantiate()` in that environment.

## Registry / GitHub (If Publishing This Rename)

- [x] `gh auth status --hostname github.com`
- [x] Create GitHub repo: `JuliaServices/Reseau.jl`
- [x] Update local remotes:

```sh
cd "$(git rev-parse --show-toplevel)"
git remote rename origin awsio
git remote add origin https://github.com/JuliaServices/Reseau.jl.git
git remote -v
```

- [x] Bootstrap CI: temporarily run only Julia **1.12** across macOS/Linux/Windows.

Notes:
- Coverage upload was removed from CI for now to avoid requiring `CODECOV_TOKEN` during bootstrap.

Remaining (manual, if publishing/registry):
- [x] Initial push to the new repo (pushed to `origin/main`).
- [ ] Copy/set repo secrets as needed:
  - [ ] `CODECOV_TOKEN` (if re-enabling Codecov)
  - [ ] `DOCUMENTER_KEY` (TagBot)
- [ ] Register `Reseau` as a new package in General.
- [ ] Decide what to do with `AwsIO` in General (leave as-is, deprecate, or archive).
