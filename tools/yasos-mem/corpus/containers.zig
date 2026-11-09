// "ArrayList/sort/HashMap": the generic-container working set.
const std = @import("std");
export fn main() callconv(.c) c_int {
    var buf: [8192]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const gpa = fba.allocator();
    var list: std.ArrayList(u32) = .empty;
    defer list.deinit(gpa);
    var i: u32 = 0;
    while (i < 16) : (i += 1) list.append(gpa, 16 - i) catch return 1;
    std.mem.sort(u32, list.items, {}, std.sort.asc(u32));
    var map: std.AutoHashMapUnmanaged(u32, u32) = .empty;
    defer map.deinit(gpa);
    for (list.items) |v| map.put(gpa, v, v * 2) catch return 1;
    return @intCast(map.count());
}
