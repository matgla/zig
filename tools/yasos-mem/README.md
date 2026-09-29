# Peak-heap measurement for the YasOS (MCU) fork

The device has 8 MB of PSRAM, so the compiler's peak live heap is the binding
constraint. `-Dpeak-heap` wraps the root allocator and prints, at exit:

    PEAK_HEAP <bytes> allocs <count> usable <bytes>

`usable` is the peak of `malloc_usable_size` over live blocks -- what the C
allocator actually holds. It used to be well above the requested bytes, because
`c_allocator` never gave a shrink back; now the two are within 0.2%.
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
-OReleaseSmall -fno-incremental` (`fs_*`: `thumb-freestanding`, which is what the
device compiles) into a **fresh cache directory**, so every run is
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

## Baselines -- 2026-09-29, branch `mcu-mem`

Peak `malloc_usable_size` bytes, before (295444886) and after this round:

| program | before | after | change |
|---|---|---|---|
| c_main | 5,730,048 | 4,607,752 | -19.6% |
| bufprint | 7,727,984 | 4,977,552 | -35.6% |
| debug_print | 23,807,352 | 15,643,384 | -34.3% |
| containers | 5,829,296 | 3,045,520 | -47.8% |
| json | 7,714,512 | 4,207,144 | -45.5% |
| fs_hello | 2,657,288 | 1,852,600 | -30.3% |
| fs_hellofmt | 5,195,504 | 2,980,640 | -42.6% |

From: tests of non-main modules left out of ZIR; link-queue/codegen-pool buffers
sized for one task when single-threaded; InternPool storage superseded by growth
freed between analysis units; ZIR instructions exact-size; c_allocator shrinks
through realloc. The generated C is identical modulo `__N` suffixes.

On the device (QEMU mps3-an524, same kernel/libc/cross, `/proc/mempeak` minus
the shell; includes the 512 KiB stack and .data): fs_hello 3,845,888 ->
3,074,304, fs_hellofmt 6,504,192 -> 4,335,872 (also no 256 KiB signal stack).

What is left, for fs_hellofmt: resident ZIR ~50% of peak, and the parse/AstGen
transient of the file being lowered ~25%.

## `-Dcpu-family=arm` -- 2026-09-29, branch `mcu-cpu-families`

The device compiler carries only the ARM CPU feature and model tables. It then
refuses every other architecture family ("this compiler was built without
support for the 'riscv' architecture family"); the family it runs on is always
kept. `apps/zig/build_zig.sh` in yasos passes it (`ZIG_CPU_FAMILIES`, default
`arm`).

zig.o under tcc -O2: .data 281,004 -> 83,420, .text 3,686,580 -> 3,565,072;
the YAFF image 4,374,736 -> 3,988,392 B, its data segment (copied to RAM at
exec) 663,600 -> 342,864.

On the device (same measurement as above, A/B from the same commit):

| program | all families | arm only | change |
|---|---|---|---|
| fs_hello | 3,073,536 | 2,875,648 | -197,888 (-6.4%) |
| fs_hellofmt | 4,400,640 | 4,137,216 | -263,424 (-6.0%) |

Generated C is byte-identical; compile times unchanged (0.90 / 1.8 s).

## ZIR eviction -- `-Dzir-budget` (c33565d33)

`ZIG_ZIR_BUDGET=<bytes>` overrides the build option at run time. Peak
`malloc_usable_size` bytes, budget 0 -> 256 KiB (MB of ZIR re-read):

| program | budget 0 | 256 KiB | change | reloaded |
|---|---|---|---|---|
| fs_hello | 1,859,072 | 1,490,520 | -20% | 0.3 |
| fs_hellofmt | 2,987,576 | 2,137,872 | -28% | 5.5 |
| c_main | 4,614,672 | 3,821,656 | -17% | 5.0 |
| json | 4,214,896 | 2,769,856 | -34% | 24 |
| debug_print | 15,664,936 | 10,293,000 | -34% | ~830 (thrashes) |

Below ~256 KiB the peak stops improving; the pinned files and the lowering of
the file being imported are what is left. Validate with
`ZIG_ZIR_POISON_EVICTED=1 ZIG_ZIR_BUDGET=1` (evict everything, poison it):
the C must be byte-identical to budget 0.

On the device (QEMU, `export ZIG_ZIR_BUDGET=...`, `/proc/mempeak` read
WITHOUT `time` -- under `time` the figure does not move with the budget):
fs_hello 2,995,968 -> 2,569,984, fs_hellofmt 4,339,456 -> 3,569,408, and five
fs_hellofmt compiles 13 s -> 8 s. Needs the device ZIR cache to hold ZIR:
yasos e0f77f0 (64-bit lseek/ftruncate; the cache files had been empty).
