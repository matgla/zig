// Device-style std.fmt: bufPrint + libc write, thumb-freestanding, as on YasOS.
const std = @import("std");
extern fn write(c_int, [*]const u8, usize) isize;
export fn main() c_int {
    var buf: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "n={d} s={s}\n", .{ 42, "x" }) catch return 1;
    _ = write(1, s.ptr, s.len);
    return 0;
}
