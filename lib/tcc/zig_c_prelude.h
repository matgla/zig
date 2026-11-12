/* Force-included (-include) by `zig -ftcc` ahead of the C the C backend wrote.
 *
 * zig.h picks its compiler flavour by macro: __GNUC__ wins over __TINYC__, and
 * tcc defines __GNUC__.  On the zig_gcc path zig.h asks __has_attribute(aligned)
 * and friends, which tcc answers "no" to, and alignment silently goes away.
 * Undefining __GNUC__ puts zig.h on its zig_tinyc path, which asserts the
 * attributes tcc really supports.
 *
 * The headers zig.h pulls in are included FIRST, while __GNUC__ is still
 * defined, so they keep their GNU spellings (__builtin_va_list and friends).
 * A freestanding compile (-nostdinc, ZIG_TCC_FREESTANDING) sees the headers in
 * lib/tcc/include only; a hosted one gets libc's string.h and math.h too. */
#include <stdarg.h>
#include <stddef.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <float.h>
#ifndef ZIG_TCC_FREESTANDING
#include <string.h>
#include <math.h>
#endif

#undef __GNUC__
#undef __GNUC_MINOR__
#undef __GNUC_PATCHLEVEL__
