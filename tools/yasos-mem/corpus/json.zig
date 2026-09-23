// "json": std.json, the heaviest of the five.
const std = @import("std");
const Rec = struct { a: u32, b: []const u8 };
export fn main() callconv(.c) c_int {
    var buf: [8192]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const gpa = fba.allocator();
    const parsed = std.json.parseFromSlice(Rec, gpa, "{\"a\":1,\"b\":\"x\"}", .{}) catch return 1;
    defer parsed.deinit();
    return @intCast(parsed.value.a);
}
