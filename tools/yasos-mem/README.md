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

## Round 3 -- 2026-09-29: the import-time lowering peak

Massif on fs_hellofmt put the whole compile's peak at one moment: `std/Io/Writer.zig`
being lowered mid-analysis, with `Io.zig` and `mem.zig` ZIR pinned by the Sema frames
that imported it. Peak `malloc_usable_size`, ZIR budget 256 KiB:

| program | c201429ad | 59fb80564 | ecdae3836 | 258559d3a |
|---|---|---|---|---|
| c_main | 3,822,728 | 3,483,136 | 3,470,352 | 3,420,688 |
| bufprint | 3,867,136 | 3,528,152 | 3,515,352 | 3,467,560 |
| debug_print | 10,295,704 | 10,292,344 | 9,860,056 | 9,859,320 |
| containers | 2,164,840 | 1,914,248 | 1,824,648 | 1,824,168 |
| json | 2,772,992 | 2,769,552 | 2,678,288 | 2,677,856 |
| fs_hello | 1,493,288 | 1,391,464 | 1,387,360 | 1,334,144 |
| fs_hellofmt | 2,138,720 | 1,931,600 | 1,867,504 | 1,850,584 |

- 59fb80564: `MultiArrayList.shrinkAndFree` compacts in place and remaps (the exact-size
  copy of the ZIR instructions, allocated while the old buffer was live, *was* the peak);
  `Ast.parse` trims its token and node lists.
- ecdae3836: files of a stripped module are lowered without `dbg_stmt` (~11% of ZIR bytes,
  own cache key). `dbg_var_*` must stay: the `.dbg_var` name strategy reads them.
  Validated by rendering `zig.c` (66.8 MB, `-Dstrip`) with and without: byte-identical.
- 258559d3a: a grown InternPool map table is freed as soon as it is rehashed.

Validation for all three: corpus C identical; `zig test` of the 8 std files (ReleaseSmall,
`--zig-lib-dir` = this tree, else the file lands in two modules) identical but for the
version string, with `ZIG_IP_POISON_RETIRED=1 ZIG_ZIR_POISON_EVICTED=1 ZIG_ZIR_BUDGET=1`.

Device (QEMU, whole-process `/proc/mempeak` incl. the 641,792 B shell): the device's
allocator hid most of the host gain -- a large block's shrink was a copy, and retired
pools stranded their bump room. With yasos 22c0068 (kernel `mremap` shrinks in place,
libc uses it) and c2d7f55 (retired pool's bump room on its free list):

| | hello | hellofmt | tcc on hellofmt.c |
|---|---|---|---|
| c201429ad, old kernel/libc | 2,387,200 | 3,247,360 | -- |
| 258559d3a, old kernel/libc | 2,216,448 | 3,113,472 | 3,444,992 |
| 258559d3a, new kernel/libc | 2,216,448 | 2,916,864 | 3,248,384 |

Left at the device hellofmt peak (2.19 MB mapped heap): 18 large mappings 1.45 MB, a
148 KB request in flight, pools 590 KB holding 288 KB live -- 243 KB free in 11 retired
pools, 204 KB of it in holes >= 4 KB (not from realloc growth: growing pool blocks in
place was tried and changed nothing). The Zig side of the same moment: AST 274 KB +
source 114 KB + AstGen ~360 KB of Writer.zig, pinned ZIR ~500 KB, InternPool ~470 KB
(FQN strings only 26 KB of it -- lazy FQNs rejected).

### The large blocks at the device peak

`.cache/zigmem/tools/mkmstat.py` (yasos sandbox) also lists every live large mapping at the
mapped peak. Sizes identify them: ZIR instructions are 9 B each, extra words 4, tokens 5, AST
nodes 13. hellofmt, before 72c08681e:

| what | bytes |
|---|---|
| Writer.zig source, tokens, nodes | 113,688 + 108,545 + 143,039 |
| Writer.zig ZIR instructions (reserved) | 148,572 (16,508 for 10,575 used) |
| Writer.zig extra, growing | 99,132 -> 148,784 in flight: the peak |
| Io.zig ZIR (pinned) | 111,105 + 141,876 |
| mem.zig ZIR (pinned, reloaded) | 103,941 + 123,716 |
| InternPool lists/maps | 81,904, 40,944, 65,540, 37,804, 32,772, 35,184 |

72c08681e reserves instructions (1.125/node) and extra (3/node) exactly: device hellofmt
2,916,864 -> 2,761,728, hello 2,216,448 -> 2,151,424. Now the peak is the moment Writer.zig's
extra is reserved; what remains there is the lowering itself (source + AST + ZIR, ~610 KB),
the pinned ZIR (~480 KB) and the InternPool (~295 KB). With yasos d05f3fd (retired pools
give back free pages at their end): hellofmt 2,720,768, hello 2,114,560.
