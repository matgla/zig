#!/usr/bin/env bash
# Measure peak live heap of a -Dpeak-heap compiler over the corpus.
# usage: measure.sh <path-to-zig> [label]
set -u
ZIG="$1"; LABEL="${2:-run}"
SP="$(cd "$(dirname "$0")" && pwd)"
OUT="${TMPDIR:-/tmp}/yasos-mem.$LABEL"; rm -rf "$OUT"; mkdir -p "$OUT"

# Programs that reach std.c need -lc, or the compile fails AFTER Sema with
# "dependency on libc must be explicitly specified" -- which still prints a
# PEAK_HEAP line, so a runner that only greps for that silently measures a
# failed compile.
flags_for() {
  case "$1" in
    c_main|bufprint) echo "-lc" ;;
    *) echo "" ;;
  esac
}

printf '%-14s %12s %12s %10s %8s %10s\n' program peak_heap peak_usable allocs files status
for f in c_main bufprint debug_print containers json; do
  cache="$OUT/cache.$f"
  log="$OUT/$f.log"
  # shellcheck disable=SC2046
  "$ZIG" build-obj "$SP/corpus/$f.zig" -target thumb-linux-musleabi -mcpu cortex_m33 \
      -ofmt=c -OReleaseSmall -fno-incremental $(flags_for "$f") \
      --cache-dir "$cache" --global-cache-dir "$cache" -femit-bin="$OUT/$f.c" > "$log" 2>&1
  rc=$?
  peak=$(sed -n 's/^PEAK_HEAP \([0-9]*\) allocs \([0-9]*\).*$/\1/p' "$log" | tail -1)
  allocs=$(sed -n 's/^PEAK_HEAP \([0-9]*\) allocs \([0-9]*\).*$/\2/p' "$log" | tail -1)
  usable=$(sed -n 's/^PEAK_HEAP .* usable \([0-9]*\)$/\1/p' "$log" | tail -1)
  nfiles=$(find "$cache" -path '*/z/*' -type f 2>/dev/null | wc -l)
  if [ "$rc" -ne 0 ] || [ ! -s "$OUT/$f.c" ]; then
    printf '%-14s %12s %12s %10s %8s %10s\n' "$f" "${peak:--}" "${usable:--}" "${allocs:--}" "$nfiles" "FAILED"
    head -3 "$log" | sed 's/^/    /'
  else
    printf '%-14s %12s %12s %10s %8s %10s\n' "$f" "$peak" "${usable:--}" "$allocs" "$nfiles" "ok"
  fi
done
echo "artifacts: $OUT"
