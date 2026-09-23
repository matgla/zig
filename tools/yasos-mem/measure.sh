#!/usr/bin/env bash
# Measure peak live heap of a -Dpeak-heap compiler over the corpus.
# usage: measure.sh <path-to-zig> [label]
set -u
ZIG="$1"; LABEL="${2:-$(basename "$(dirname "$(dirname "$ZIG")")")}"
SP="$(cd "$(dirname "$0")" && pwd)"
OUT="$SP/out.$LABEL"; rm -rf "$OUT"; mkdir -p "$OUT"
printf '%-14s %12s %10s %8s\n' program peak_heap allocs files
for f in c_main bufprint debug_print containers json; do
  src="$SP/corpus/$f.zig"
  # fresh cache dir each time: cold, comparable, and never reuses another arm's ZIR
  cache="$OUT/cache.$f"
  log=$("$ZIG" build-obj "$src" -target thumb-linux-musleabi -mcpu cortex_m33 \
        -ofmt=c -OReleaseSmall -fno-incremental --cache-dir "$cache" \
        --global-cache-dir "$cache" -femit-bin="$OUT/$f.c" 2>&1)
  peak=$(printf '%s\n' "$log" | sed -n 's/^PEAK_HEAP \([0-9]*\) allocs \([0-9]*\)$/\1/p' | tail -1)
  allocs=$(printf '%s\n' "$log" | sed -n 's/^PEAK_HEAP \([0-9]*\) allocs \([0-9]*\)$/\2/p' | tail -1)
  nfiles=$(find "$cache" -path '*/z/*' -type f 2>/dev/null | wc -l)
  if [ -z "$peak" ]; then
    printf '%-14s %12s %10s %8s\n' "$f" FAIL - -
    printf '%s\n' "$log" | tail -4 | sed 's/^/    /'
  else
    printf '%-14s %12s %10s %8s\n' "$f" "$peak" "$allocs" "$nfiles"
  fi
done
