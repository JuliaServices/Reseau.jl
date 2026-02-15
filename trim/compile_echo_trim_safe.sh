#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_PATH="${1:-/tmp/reseau_trim_verify_latest.log}"
JULIA_BIN="${JULIA_BIN:-julia}"

# Install JuliaC once in the default Julia 1.12 environment if needed.
"$JULIA_BIN" --startup-file=no --history-file=no --project=@v1.12 -e 'using JuliaC' >/dev/null 2>&1 || \
    "$JULIA_BIN" --startup-file=no --history-file=no --project=@v1.12 -e 'using Pkg; Pkg.add("JuliaC")'

cd "$ROOT_DIR/trim"
JULIA_NUM_THREADS="${JULIA_NUM_THREADS:-1}" "$JULIA_BIN" \
    --startup-file=no --history-file=no --project=@v1.12 -m JuliaC \
    --output-exe echo_trim_safe \
    --project=.. \
    --experimental --trim=safe \
    echo_trim_safe.jl >"$LOG_PATH" 2>&1
