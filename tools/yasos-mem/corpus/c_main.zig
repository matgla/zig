// "C-main hello": no Zig start code, writes through std.c. Smallest realistic program.
const std = @import("std");
export fn main() callconv(.c) c_int {
    const msg = "hello\n";
    _ = std.c.write(1, msg.ptr, msg.len);
    return 0;
}
