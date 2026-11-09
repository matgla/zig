// "bufPrint": pulls std.fmt but not the full Io/debug stack.
const std = @import("std");
export fn main() callconv(.c) c_int {
    var buf: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "n={d} s={s}\n", .{ 42, "x" }) catch return 1;
    _ = std.c.write(1, s.ptr, s.len);
    return 0;
}
