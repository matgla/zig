//! The C backend's output, compiled and linked by tinycc.
//!
//! With `-ftcc` the compilation targets `-ofmt=c` internally: Sema, codegen and
//! `link.C` are the C backend exactly as `-ofmt=c` runs them.  `link.C` writes
//! the C next to the requested output (`<bin>.c`), and at the end of its flush
//! runs tcc on that file, which compiles it and links it with the other inputs
//! into the binary the user asked for, in the target's real object format.
//!
//! tcc is a child process: `ZIG_TCC` if set, otherwise `-Dtcc-exe` of the
//! compiler's build (default `tcc`, found through PATH).  A separate process
//! keeps tcc's memory out of the compiler's and, on YasOS, lets the compiler be
//! swapped out while it waits in waitpid.  A tcc is built for one target (a cross
//! `armv8m-tcc` makes ARM code whatever it runs on); its lib directory
//! (libtcc1.a, headers) is the one it was configured with.
//!
//! Extra tcc options: `--tcc-arg <arg>` (repeatable) and `ZIG_TCC_FLAGS`
//! (split at spaces), after the ones derived here, so they win.

const Tcc = @This();

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const Path = std.Build.Cache.Path;

const Compilation = @import("../Compilation.zig");
const link = @import("../link.zig");
const target_util = @import("../target.zig");

/// What a compilation that goes through tcc remembers.
pub const Config = struct {
    /// The object format of the binary tcc writes.  The compilation itself
    /// targets `.c`.
    ofmt: std.Target.ObjectFormat,
    /// `--tcc-arg` values, in order.
    args: []const []const u8 = &.{},
};

/// Compilations whose backend would be Zig's self-hosted ARM backend go
/// through C and tcc instead, unless told otherwise (`-fno-tcc`).
pub const default_on = if (@hasDecl(build_options, "tcc_default")) build_options.tcc_default else false;
/// The compiler runs on YasOS: a native target is YasOS (thumb-linux-musleabi
/// in Zig's eyes, but every system call goes through the YasOS libc).
pub const yasos_host = if (@hasDecl(build_options, "yasos_host")) build_options.yasos_host else false;
const default_tcc: []const u8 = if (@hasDecl(build_options, "tcc_exe")) build_options.tcc_exe else "tcc";

/// Whether a compilation for `target` goes through tcc.  `explicit` is
/// `-ftcc`/`-fno-tcc`; `use_llvm` is `-fllvm`/`-fno-llvm`.
pub fn wanted(explicit: ?bool, target: *const std.Target, use_llvm: ?bool) bool {
    if (explicit) |x| return x;
    if (!default_on) return false;
    if (use_llvm == true or target.ofmt == .c) return false;
    return target_util.zigBackend(target, false) == .stage2_arm;
}

/// Switches a resolved target over to the C backend for a tcc compilation and
/// returns the configuration that remembers the real object format.
pub fn adopt(target: *std.Target, args: []const []const u8) Config {
    const cfg: Config = .{ .ofmt = target.ofmt, .args = args };
    target.ofmt = .c;
    return cfg;
}

/// `lowMemoryDefaults`' choices, for when the environment names none.  Not set
/// with setenv: YasOS's libc has none.
var default_spill_dir: ?[*:0]const u8 = null;
var default_ip_hints: ?[*:0]const u8 = null;

/// Where rendered C, references and saved bodies are spilled: `ZIG_C_SPILL_DIR`,
/// else the YasOS default, else nowhere.
pub fn spillDir() ?[*:0]const u8 {
    if (!builtin.link_libc) return null;
    return std.c.getenv("ZIG_C_SPILL_DIR") orelse default_spill_dir;
}

/// The InternPool size hints file: `ZIG_IP_HINTS`, else the YasOS default.
pub fn ipHintsPath() ?[*:0]const u8 {
    if (!builtin.link_libc) return null;
    return std.c.getenv("ZIG_IP_HINTS") orelse default_ip_hints;
}

/// A compiler on YasOS always compiles with its low-memory settings, unless the
/// environment names its own: rendered C spilled to the global cache's `tmp`
/// (the card; the directory has to exist or nothing spills), and InternPool
/// sizes kept per root name in `h`, starting from the ones shipped in the lib
/// directory (the configurer's, measured on the PC: its first compile would
/// otherwise grow its tables by doubling, 4 MB more at the peak).
pub fn lowMemoryDefaults(arena: Allocator, io: std.Io, dirs: *const std.zig.Directories, root_name: []const u8) void {
    if (comptime !yasos_host) return;
    defaults(arena, io, dirs, root_name) catch |err| std.log.warn("no low-memory defaults: {t}", .{err});
}

fn defaults(arena: Allocator, io: std.Io, dirs: *const std.zig.Directories, root_name: []const u8) !void {
    const cache = dirs.global_cache;
    // A failed createDirPath does not mean the directory is missing: YasOS FAT fails a stat
    // of one after a compile that ran out of memory.  Nothing spills where it truly is.
    cache.handle.createDirPath(io, "tmp") catch {};
    default_spill_dir = try cache.joinZ(arena, &.{"tmp"});
    cache.handle.createDirPath(io, "h") catch {};
    const name = try std.fmt.allocPrint(arena, "ip-hints-{s}", .{root_name});
    const sub = try std.fs.path.join(arena, &.{ "h", name });
    if (cache.handle.access(io, sub, .{})) |_| {} else |_| {
        const shipped = try std.fs.path.join(arena, &.{ "tcc", "yasos", name });
        if (dirs.zig_lib.handle.readFileAlloc(io, shipped, arena, .limited(4096))) |bytes| {
            try cache.handle.writeFile(io, .{ .sub_path = sub, .data = bytes });
        } else |_| {}
    }
    default_ip_hints = try cache.joinZ(arena, &.{sub});
}

/// `ZIG_TCC`, else `-Dtcc-exe`.
fn tccExe(comp: *Compilation) []const u8 {
    return comp.environ_map.get("ZIG_TCC") orelse default_tcc;
}

const Argv = struct {
    arena: Allocator,
    list: std.ArrayList([]const u8) = .empty,

    fn add(a: *Argv, arg: []const u8) Allocator.Error!void {
        try a.list.append(a.arena, arg);
    }

    fn addFmt(a: *Argv, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        try a.add(try std.fmt.allocPrint(a.arena, fmt, args));
    }

    fn addPath(a: *Argv, p: Path) Allocator.Error!void {
        try a.add(try p.toString(a.arena));
    }
};

/// Compiles `c_src` (the C backend's output) with the compilation's other
/// inputs into `out` with a tcc child process.  Called by `link.C` at the end
/// of its flush.
pub fn build(
    comp: *Compilation,
    arena: Allocator,
    lf: *link.File,
    cfg: Config,
    linker_script: ?Path,
    c_src: Path,
    out: Path,
) link.Error!void {
    const diags = &comp.link_diags;
    const target = &comp.root_mod.resolved_target.result;
    const env = comp.environ_map;

    const zig_lib = comp.dirs.zig_lib;
    const output_mode = comp.config.output_mode;
    const freestanding = target.os.tag == .freestanding or target.os.tag == .other;
    // tcc here is a YasOS compiler: Linux on a Thumb (M-profile) core is YasOS.
    const yasos = target.os.tag == .linux and target.cpu.arch.isThumb();
    // The bridge between Zig's Linux view and YasOS, and compiler_rt (the
    // u128/f128 helpers zig.h calls), built for YasOS: shipped in the zig lib
    // directory of the device compiler (yasos.zig apps/zig/build_zig.sh).
    const yasos_runtime = yasos and if (zig_lib.handle.access(comp.io, "tcc/yasos/yasos_compat.o", .{})) |_| true else |_| false;

    var o: Argv = .{ .arena = arena };
    try o.add(tccExe(comp));
    // A `--tcc-arg -O...` replaces the level the optimize mode would pick, rather
    // than following it on the command line: zig build's maker compiles the
    // configurer's C at -O0, which runs once and for a moment, while keeping
    // ReleaseSmall for how much C there is to compile.
    const own_level = for (cfg.args) |arg| {
        if (std.mem.startsWith(u8, arg, "-O")) break true;
    } else false;
    if (!own_level) try o.add(switch (comp.root_mod.optimize_mode) {
        .debug => "-O0",
        .small => "-Os",
        .fast, .safe => "-O2",
    });
    // The C backend's output is warning-heavy by nature (unused labels and
    // variables, casts); its correctness is Zig's business.
    try o.add("-w");
    try o.add("-ffunction-sections");
    try o.add("-fdata-sections");
    try o.addFmt("-I{s}", .{zig_lib.path orelse "."});
    if (freestanding) {
        // No libc: the freestanding headers Zig ships for tcc, nothing tcc
        // was configured with and nothing of the host's.
        try o.add("-nostdinc");
        try o.add("-nostdlib");
        try o.add("-fno-pic");
        try o.add("-static");
        try o.add("-DZIG_TCC_FREESTANDING=1");
        try o.addFmt("-I{s}", .{try zig_lib.join(arena, &.{ "tcc", "include" })});
    }
    try o.add("-include");
    try o.add(try zig_lib.join(arena, &.{ "tcc", "zig_c_prelude.h" }));
    if (yasos) try o.add("-fvisibility=hidden");
    if (yasos_runtime) {
        // As the device compiler itself is built: Zig's Linux view of
        // lseek/ftruncate is 64-bit, yasos_compat.o has those.
        try o.add("-Dlseek=yz_lseek64");
        try o.add("-Dftruncate=yz_ftruncate64");
    }
    switch (output_mode) {
        .Obj => {},
        .Exe, .Lib => {
            if (lf.gc_sections) try o.add("-Wl,--gc-sections");
            if (cfg.ofmt == .elf and freestanding) try o.add("-Wl,-oformat=elf32-littlearm");
            // YasOS loads YAFF images.
            if (yasos) try o.add("-Wl,-oformat=yaff");
            if (linker_script) |script| {
                try o.add("-T");
                try o.add(try script.toString(arena));
            }
            // YasOS reserves a program's whole stack at exec.
            if (yasos and output_mode == .Exe) try o.add("-stack-size=131072");
        },
    }
    // tcc keeps saved function bodies in the same place the compiler spills.
    if (comptime yasos_host) if (spillDir()) |dir| try o.addFmt("-fspill-dir={s}", .{std.mem.span(dir)});
    for (cfg.args) |arg| try o.add(arg);
    if (env.get("ZIG_TCC_FLAGS")) |flags| {
        var it = std.mem.tokenizeScalar(u8, flags, ' ');
        while (it.next()) |arg| try o.add(arg);
    }

    switch (output_mode) {
        .Exe => {},
        .Obj => try o.add("-c"),
        .Lib => switch (comp.config.link_mode) {
            .dynamic => try o.add("-shared"),
            .static => return diags.fail("-ftcc: static libraries are not supported; build an object", .{}),
        },
    }
    try o.add("-o");
    try o.addPath(out);
    try o.addPath(c_src);
    if (output_mode != .Obj) {
        for (comp.c_source_files) |csf| try o.add(csf.src_path);
        for (comp.link_inputs) |input| switch (input) {
            .object, .archive => |obj| try o.addPath(obj.path),
            .dso => |dso| try o.addPath(dso.path),
            .res, .tbd => {},
        };
        if (yasos_runtime) for ([_][]const u8{ "yasos_compat.o", "compiler_rt.o" }) |name| {
            try o.add(try zig_lib.join(arena, &.{ "tcc", "yasos", name }));
        };
    }

    if (comp.verbose_link) {
        const cmd: std.zig.SubprocessCommand = .{ .argv = o.list.items };
        std.debug.print("{f}\n", .{cmd});
    }

    const io = comp.io;
    // stdout ignored: under `--listen=-` the compiler's stdout is the build
    // runner's protocol.  stderr is inherited, not piped: tcc's diagnostics go
    // where the compiler's own do, and the compiler has nothing to read, so it
    // goes straight to waiting.  That matters on YasOS, where only a process
    // waiting in waitpid can be swapped out to make room for tcc.
    var child = std.process.spawn(io, .{
        .argv = o.list.items,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| return diags.fail("-ftcc: cannot run '{s}': {t} (set ZIG_TCC)", .{ tccExe(comp), err });
    const term = child.wait(io) catch |err| return diags.fail("-ftcc: waiting for tcc: {t}", .{err});
    if (!term.success()) return diags.fail("tcc {f}", .{term});
}
