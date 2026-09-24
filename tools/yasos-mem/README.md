# Peak-heap measurement for the YasOS (MCU) fork

The device has 8 MB of PSRAM, so the compiler's peak live heap is the binding
constraint. `-Dpeak-heap` wraps the root allocator and prints, at exit:

    PEAK_HEAP <bytes> allocs <count>
    IP_ARENA <n> IP_LIVE <n> IP_RETIRED <n> IP_MAPS <n> IP_RMAPS <n> IP_SLACK <n>

The second line is an `InternPool` census: how much of the per-thread storage is
live list buffers, how much is buffers superseded by a growth (kept on purpose --
callers hold slices into them), how much is shard map tables, and how much was
arena node slack. Both are reported from an `atexit` hook, because a one-shot
compile leaves through `cleanExit` and never tears the pool down.

## Use

    zig build -Dpeak-heap -Ddev=cbe -Dsingle-threaded -Dforce-link-libc \
              -Doptimize=ReleaseFast --prefix <dir>
    tools/yasos-mem/measure.sh <dir>/bin/zig <label>

Each program compiles `-target thumb-linux-musleabi -mcpu cortex_m33 -ofmt=c
-OReleaseSmall -fno-incremental` into a **fresh cache directory**, so every run is
cold and no arm reuses another's ZIR. `files` counts ZIR cache entries, i.e. how
many files AstGen actually lowered.

Two traps the runner now handles, both of which cost real measurements:

- **`-Donly-c` pins `-Ddev=.bootstrap`.** Always pass `-Ddev=` explicitly or you
  measure a different compiler.
- **A failed compile still prints PEAK_HEAP.** `c_main` and `bufprint` reach
  `std.c` and need `-lc`; without it they fail *after* Sema with "dependency on
  libc must be explicitly specified", emit a zero-byte file, and report a heap
  figure for a compile that never finished. The runner passes the flags each
  program needs and reports FAILED on a non-zero exit or an empty output.

## Baselines — 2026-09-24, branch `mcu-mem`

| program | peak heap | allocs | files |
|---|---|---|---|
| c_main | 5,465,528 | 3,865 | 12 |
| bufprint | 7,129,499 | 9,463 | 21 |
| debug_print | 22,529,156 | 224,919 | 70 |
| containers | 5,365,402 | 22,403 | 23 |
| json | 7,190,567 | 48,689 | 35 |

Taken at the tip of `mcu-mem`, which does **not** include the in-flight
`Builtin.hash`/`auto_hash` fixes being developed in the main tree; expect these to
move once those land.

`c_main` lowers 12 files and still costs nearly as much as `containers`, which
lowers 23: reaching `std.c.write` drags `std/c.zig` (774,682 B of ZIR), which
pulls `os/linux.zig` (676,617) and `os/linux/syscalls.zig` (472,617). Those three
are 1.92 MB of the 2.43 MB that `c_main` lowers at all. A YasOS OS tag in
`std.Target` is the lever there.
