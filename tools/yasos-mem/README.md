# Peak-heap measurement for the YasOS (MCU) fork

The device has 8 MB of PSRAM, so the compiler's peak live heap is the binding
constraint. `-Dpeak-heap` wraps the root allocator and prints

    PEAK_HEAP <bytes> allocs <count>

to stderr at exit (needs libc for `atexit`; inert otherwise).

## Use

    zig build -Dpeak-heap -Ddev=cbe -Dsingle-threaded -Dforce-link-libc \
              -Doptimize=ReleaseFast --prefix <dir>
    tools/yasos-mem/measure.sh <dir>/bin/zig <label>

Each program is compiled `-target thumb-linux-musleabi -mcpu cortex_m33 -ofmt=c
-OReleaseSmall -fno-incremental` into a **fresh cache directory**, so every run is
cold and no arm reuses another's ZIR. `files` counts ZIR cache entries, i.e. how
many files AstGen actually lowered.

`-Donly-c` pins `-Ddev=.bootstrap`; always pass `-Ddev=` explicitly or you measure
a different compiler.

## Baselines — 2026-09-23, at the tip of `yasos-low-memory`

| program | peak heap | allocs | files |
|---|---|---|---|
| c_main | 7,157,720 | 3,769 | 12 |
| bufprint | 9,007,553 | 9,310 | 21 |
| debug_print | 23,411,563 | 224,794 | 70 |
| containers | 5,603,980 | 22,310 | 23 |
| json | 7,711,673 | 48,584 | 35 |

`c_main` costs more than `containers` despite lowering half as many files: touching
`std.c.write` drags `std/c.zig` (774,682 B of ZIR), which pulls `os/linux.zig`
(676,617) and `os/linux/syscalls.zig` (472,617). A program that avoids `std.c`
entirely sits at 5.6 MB. The 7.6 MB "floor" quoted before this corpus existed was
that effect, not a lower bound.
