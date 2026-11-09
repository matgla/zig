// "std.debug.print hello": drags std.Io + Io.Threaded, the heaviest small program.
const std = @import("std");
pub fn main() void {
    std.debug.print("hello {d}\n", .{@as(u32, 1)});
}
