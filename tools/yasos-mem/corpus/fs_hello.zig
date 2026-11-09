// Device-style hello: no std at all, libc puts. Compiled for thumb-freestanding, as on YasOS.
extern fn puts([*:0]const u8) c_int;
export fn main() c_int {
    _ = puts("hello");
    return 0;
}
