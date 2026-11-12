
const Threaded = @This();

pub const builtin = @import("builtin");
pub const native_os = builtin.os.tag;
pub const is_windows = native_os == .windows;
pub const is_darwin = native_os.isDarwin();
const is_debug = builtin.mode == .debug;

pub const std = @import("../std.zig");
pub const windows_impl = @import("Threaded/windows.zig");
pub const wasi_impl = @import("Threaded/wasi.zig");
pub const darwin_impl = @import("Threaded/darwin.zig");
pub const net_impl = @import("Threaded/net.zig");
pub const Io = std.Io;
pub const net = std.Io.net;
pub const File = std.Io.File;
pub const Dir = std.Io.Dir;
pub const HostName = net.HostName;
pub const IpAddress = net.IpAddress;
pub const process = std.process;
pub const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
pub const assert = std.debug.assert;
pub const posix = std.posix;
pub const windows = std.os.windows;
pub const ws2_32 = windows.ws2_32;

/// Thread-safe.
///
/// Used for:
/// * allocating `Io.Future` and `Io.Group` closures.
/// * formatting spawning child processes
/// * scanning environment variables on some targets
/// * memory-mapping when mmap or equivalent is not available
allocator: Allocator,
mutex: Io.Mutex = .init,
cond: Io.Condition = .init,
run_queue: std.SinglyLinkedList = .{},
join_requested: bool = false,
stack_size: usize,
/// All threads are spawned detached; this is how we wait until they all exit.
wait_group: WaitGroup = .init,
async_limit: Io.Limit,
concurrent_limit: Io.Limit = .unlimited,
/// Error from calling `std.Thread.getCpuCount` in `init`.
cpu_count_error: ?std.Thread.CpuCountError,
/// Number of threads that are unavailable to take tasks. To calculate
/// available count, subtract this from either `async_limit` or
/// `concurrent_limit`.
busy_count: usize = 0,
worker_threads: std.atomic.Value(?*Thread),
pid: Pid = .unknown,

have_signal_handler: bool,
old_sig_io: if (have_sig_io) posix.Sigaction else void,
old_sig_pipe: if (have_sig_pipe) posix.Sigaction else void,

use_sendfile: UseSendfile = .default,
use_copy_file_range: UseCopyFileRange = .default,
use_fcopyfile: UseFcopyfile = .default,
use_fchmodat2: UseFchmodat2 = .default,
disable_memory_mapping: bool,

stderr_writer: File.Writer = .{
    .io = undefined,
    .interface = File.Writer.initInterface(&.{}),
    .file = if (is_windows) undefined else .stderr(),
    .mode = .streaming,
},
stderr_mode: Io.Terminal.Mode = .no_color,
stderr_writer_initialized: bool = false,
stderr_mutex: Io.Mutex = .init,
stderr_mutex_locker: std.Thread.Id = Thread.invalid_id,
stderr_mutex_lock_count: usize = 0,

argv0: Argv0,
/// Protected by `mutex`. Determines whether `environ` has been
/// memoized based on `process_environ`.
environ_initialized: bool,
environ: Environ,

dl: Dl = .init,

null_file: NullFile = .{},
random_file: RandomFile = .{},
pipe_file: PipeFile = .{},

csprng: Csprng = .uninitialized,

system_basic_information: SystemBasicInformation = .{},

process_spawn_mutex: if (is_windows) Io.Mutex else void = if (is_windows) .init else {},

const SystemBasicInformation = if (!is_windows) struct {} else struct {
    buffer: windows.SYSTEM.BASIC_INFORMATION = undefined,
    initialized: std.atomic.Value(bool) = .{ .raw = false },
};

const Dl = switch (native_os) {
    .windows => struct {
        iphlpapi_dll: std.atomic.Value(?*anyopaque),
        ConvertInterfaceNameToLuidW: std.atomic.Value(?*const fn (
            InterfaceName: [*:0]const windows.WCHAR,
            InterfaceLuid: *windows.NET.LUID,
        ) callconv(.winapi) windows.Win32Error),
        ConvertInterfaceLuidToIndex: std.atomic.Value(?*const fn (
            InterfaceLuid: *const windows.NET.LUID,
            InterfaceIndex: *windows.NET.IFINDEX,
        ) callconv(.winapi) windows.Win32Error),
        ConvertInterfaceIndexToLuid: std.atomic.Value(?*const fn (
            InterfaceIndex: std.os.windows.NET.IFINDEX,
            InterfaceLuid: *std.os.windows.NET.LUID,
        ) callconv(.winapi) windows.Win32Error),
        ConvertInterfaceLuidToNameW: std.atomic.Value(?*const fn (
            InterfaceLuid: *const std.os.windows.NET.LUID,
            InterfaceName: std.os.windows.PWSTR,
            Length: std.os.windows.SIZE_T,
        ) callconv(.winapi) std.os.windows.Win32Error),

        dnsapi_dll: std.atomic.Value(?*anyopaque),
        DnsQueryEx: std.atomic.Value(?*const fn (
            pQueryRequest: *const windows.DNS.QUERY.REQUEST,
            pQueryResults: *windows.DNS.QUERY.RESULT,
            pCancelHandle: ?*windows.DNS.QUERY.CANCEL,
        ) callconv(.winapi) windows.DNS.STATUS),
        //DnsCancelQuery: std.atomic.Value(?*const fn (
        //    pCancelHandle: *const windows.DNS.QUERY.CANCEL,
        //) callconv(.winapi) windows.DNS.STATUS),
        DnsFree: std.atomic.Value(?*const fn (
            pRecordList: ?*anyopaque,
            FreeType: windows.DNS.FREE_TYPE,
        ) callconv(.winapi) void),

        const init: Dl = .{
            .iphlpapi_dll = .init(null),
            .ConvertInterfaceNameToLuidW = .init(null),
            .ConvertInterfaceLuidToIndex = .init(null),
            .ConvertInterfaceIndexToLuid = .init(null),
            .ConvertInterfaceLuidToNameW = .init(null),

            .dnsapi_dll = .init(null),
            .DnsQueryEx = .init(null),
            //.DnsCancelQuery = .init(null),
            .DnsFree = .init(null),
        };
        fn deinit(dl: *Dl) void {
            if (dl.iphlpapi_dll.raw) |iphlpapi_dll| switch (windows.ntdll.LdrUnloadDll(iphlpapi_dll)) {
                .SUCCESS => {},
                else => |status| windows.unexpectedStatus(status) catch {},
            };
            dl.* = .init;
        }
    },
    else => struct {
        const init: Dl = .{};
        fn deinit(_: Dl) void {}
    },
};

pub const Csprng = struct {
    rng: std.Random.DefaultCsprng,

    pub const uninitialized: Csprng = .{ .rng = .{
        .state = undefined,
        .offset = std.math.maxInt(usize),
    } };

    pub const seed_len = std.Random.DefaultCsprng.secret_seed_length;

    pub fn isInitialized(c: *const Csprng) bool {
        return c.rng.offset != std.math.maxInt(usize);
    }
};

pub const Argv0 = switch (native_os) {
    .openbsd, .haiku => struct {
        value: ?[*:0]const u8,

        pub const empty: Argv0 = .{ .value = null };

        pub fn init(args: process.Args) Argv0 {
            return .{ .value = args.vector[0] };
        }
    },
    else => struct {
        pub const empty: Argv0 = .{};

        pub fn init(args: process.Args) Argv0 {
            _ = args;
            return .{};
        }
    },
};

pub const Environ = struct {
    /// Unmodified data directly from the OS.
    process_environ: process.Environ,
    /// Protected by `mutex`. Memoized based on `process_environ`. Tracks whether the
    /// environment variables are present, ignoring their value.
    exist: Exist = .{},
    /// Protected by `mutex`. Memoized based on `process_environ`.
    string: String = .{},
    /// ZIG_PROGRESS
    zig_progress_file: std.Progress.ParentFileError!File = error.EnvironmentVariableMissing,
    /// Protected by `mutex`. Tracks the problem, if any, that occurred when
    /// trying to scan environment variables.
    ///
    /// Errors are only possible on WASI.
    err: ?Error = null,

    pub const empty: Environ = .{ .process_environ = .empty };

    pub const Error = Allocator.Error || Io.UnexpectedError;

    pub const Exist = struct {
        NO_COLOR: bool = false,
        CLICOLOR_FORCE: bool = false,
    };

    pub const String = switch (native_os) {
        .windows, .wasi => struct {},
        else => struct {
            PATH: ?[:0]const u8 = null,
            DEBUGINFOD_CACHE_PATH: ?[:0]const u8 = null,
            XDG_CACHE_HOME: ?[:0]const u8 = null,
            HOME: ?[:0]const u8 = null,
            TERM: ?[:0]const u8 = null,
        },
    };

    pub fn scan(environ: *Environ, allocator: Allocator) void {
        if (is_windows) {
            // This value expires with any call that modifies the environment,
            // which is outside of this Io implementation's control, so references
            // must be short-lived.
            const peb = windows.peb();
            assert(windows.ntdll.RtlEnterCriticalSection(peb.FastPebLock) == .SUCCESS);
            defer assert(windows.ntdll.RtlLeaveCriticalSection(peb.FastPebLock) == .SUCCESS);
            const ptr = peb.ProcessParameters.Environment;

            var i: usize = 0;
            while (ptr[i] != 0) {
                // There are some special environment variables that start with =,
                // so we need a special case to not treat = as a key/value separator
                // if it's the first character.
                // https://devblogs.microsoft.com/oldnewthing/20100506-00/?p=14133
                const key_start = i;
                if (ptr[i] == '=') i += 1;
                while (ptr[i] != 0 and ptr[i] != '=') : (i += 1) {}
                const key_w = ptr[key_start..i];

                const value_start = i + 1;
                while (ptr[i] != 0) : (i += 1) {} // skip over '=' and value
                const value_w = ptr[value_start..i];
                i += 1; // skip over null byte

                if (windows.eqlIgnoreCaseWtf16(key_w, &.{ 'N', 'O', '_', 'C', 'O', 'L', 'O', 'R' })) {
                    environ.exist.NO_COLOR = true;
                } else if (windows.eqlIgnoreCaseWtf16(key_w, &.{ 'C', 'L', 'I', 'C', 'O', 'L', 'O', 'R', '_', 'F', 'O', 'R', 'C', 'E' })) {
                    environ.exist.CLICOLOR_FORCE = true;
                } else if (windows.eqlIgnoreCaseWtf16(key_w, &.{ 'Z', 'I', 'G', '_', 'P', 'R', 'O', 'G', 'R', 'E', 'S', 'S' })) {
                    environ.zig_progress_file = file: {
                        var value_buf: [std.fmt.count("{d}", .{std.math.maxInt(usize)})]u8 = undefined;
                        const len = std.unicode.calcWtf8Len(value_w);
                        if (len > value_buf.len) break :file error.UnrecognizedFormat;
                        assert(std.unicode.wtf16LeToWtf8(&value_buf, value_w) == len);
                        break :file .{
                            .handle = @ptrFromInt(std.fmt.parseInt(usize, value_buf[0..len], 10) catch
                                break :file error.UnrecognizedFormat),
                            .flags = .{ .nonblocking = true },
                        };
                    };
                }
                comptime assert(@sizeOf(String) == 0);
            }
        } else if (native_os == .wasi and !builtin.link_libc) {
            var environ_size: usize = undefined;
            var environ_buf_size: usize = undefined;

            switch (std.os.wasi.environ_sizes_get(&environ_size, &environ_buf_size)) {
                .SUCCESS => {},
                else => |err| {
                    environ.err = posix.unexpectedErrno(err);
                    return;
                },
            }
            if (environ_size == 0) return;

            const wasi_environ = allocator.alloc([*:0]u8, environ_size) catch |err| {
                environ.err = err;
                return;
            };
            defer allocator.free(wasi_environ);
            const wasi_environ_buf = allocator.alloc(u8, environ_buf_size) catch |err| {
                environ.err = err;
                return;
            };
            defer allocator.free(wasi_environ_buf);

            switch (std.os.wasi.environ_get(wasi_environ.ptr, wasi_environ_buf.ptr)) {
                .SUCCESS => {},
                else => |err| {
                    environ.err = posix.unexpectedErrno(err);
                    return;
                },
            }

            for (wasi_environ) |env| {
                const pair = std.mem.sliceTo(env, 0);
                var parts = std.mem.splitScalar(u8, pair, '=');
                const key = parts.first();
                if (std.mem.eql(u8, key, "NO_COLOR")) {
                    environ.exist.NO_COLOR = true;
                } else if (std.mem.eql(u8, key, "CLICOLOR_FORCE")) {
                    environ.exist.CLICOLOR_FORCE = true;
                }
                comptime assert(@sizeOf(String) == 0);
            }
        } else {
            for (environ.process_environ.block.slice) |opt_entry| {
                const entry = opt_entry.?;
                var entry_i: usize = 0;
                while (entry[entry_i] != 0 and entry[entry_i] != '=') : (entry_i += 1) {}
                const key = entry[0..entry_i];

                var end_i: usize = entry_i;
                while (entry[end_i] != 0) : (end_i += 1) {}
                const value = entry[entry_i + 1 .. end_i :0];

                if (std.mem.eql(u8, key, "NO_COLOR")) {
                    environ.exist.NO_COLOR = true;
                } else if (std.mem.eql(u8, key, "CLICOLOR_FORCE")) {
                    environ.exist.CLICOLOR_FORCE = true;
                } else if (std.mem.eql(u8, key, "ZIG_PROGRESS")) {
                    environ.zig_progress_file = file: {
                        break :file .{
                            .handle = std.fmt.parseInt(u31, value, 10) catch
                                break :file error.UnrecognizedFormat,
                            .flags = .{ .nonblocking = true },
                        };
                    };
                } else inline for (@typeInfo(String).@"struct".field_names) |field_name| {
                    if (std.mem.eql(u8, key, field_name)) @field(environ.string, field_name) = value;
                }
            }
        }
    }
};

pub const NullFile = switch (native_os) {
    .windows => struct {
        handle: ?windows.HANDLE = null,

        fn deinit(this: *@This()) void {
            if (this.handle) |handle| {
                windows.CloseHandle(handle);
                this.handle = null;
            }
        }
    },
    .wasi, .tvos, .watchos => struct {
        fn deinit(this: @This()) void {
            _ = this;
        }
    },
    else => struct {
        fd: posix.fd_t = -1,

        fn deinit(this: *@This()) void {
            if (this.fd >= 0) {
                closeFd(this.fd);
                this.fd = -1;
            }
        }
    },
};

pub const RandomFile = switch (native_os) {
    .windows => NullFile,
    else => if (use_dev_urandom) NullFile else struct {
        fn deinit(this: @This()) void {
            _ = this;
        }
    },
};

pub const PipeFile = switch (native_os) {
    .windows => struct {
        handle: ?windows.HANDLE = null,

        fn deinit(this: *@This()) void {
            if (this.handle) |handle| {
                windows.CloseHandle(handle);
                this.handle = null;
            }
        }
    },
    else => struct {
        fn deinit(this: @This()) void {
            _ = this;
        }
    },
};

pub const Pid = if (native_os == .linux) enum(posix.pid_t) {
    unknown = 0,
    _,
} else enum(u0) { unknown = 0 };

pub const UseSendfile = if (have_sendfile) enum {
    enabled,
    disabled,
    pub const default: UseSendfile = .enabled;
} else enum {
    disabled,
    pub const default: UseSendfile = .disabled;
};

pub const UseCopyFileRange = if (have_copy_file_range) enum {
    enabled,
    disabled,
    pub const default: UseCopyFileRange = .enabled;
} else enum {
    disabled,
    pub const default: UseCopyFileRange = .disabled;
};

pub const UseFcopyfile = if (have_fcopyfile) enum {
    enabled,
    disabled,
    pub const default: UseFcopyfile = .enabled;
} else enum {
    disabled,
    pub const default: UseFcopyfile = .disabled;
};

pub const UseFchmodat2 = if (have_fchmodat2 and !have_fchmodat_flags) enum {
    enabled,
    disabled,
    pub const default: UseFchmodat2 = .enabled;
} else enum {
    disabled,
    pub const default: UseFchmodat2 = .disabled;
};

pub const apc_align = @max(default_fn_align, 2);

const default_fn_align = switch (builtin.mode) {
    .debug, .safe, .fast => switch (builtin.cpu.arch) {
        else => |arch| @compileError("Unsupported architecture: " ++ @tagName(arch)),
        .arm, .thumb => 4,
        .aarch64, .x86, .x86_64 => 16,
    },
    .small => 1,
};

const Runnable = struct {
    node: std.SinglyLinkedList.Node,
    startFn: *const fn (*Runnable, *Thread, *Threaded) void,
};

const Group = struct {
    ptr: *Io.Group,

    /// Returns a correctly-typed pointer to the `Io.Group.token` field.
    ///
    /// The status indicates how many pending tasks are in the group, whether the group has been
    /// canceled, and whether the group has been awaited.
    ///
    /// Note that the zero value of `Status` intentionally represents the initial group state (empty
    /// with no awaiters). This is a requirement of `Io.Group`.
    fn status(g: Group) *std.atomic.Value(Status) {
        return @ptrCast(&g.ptr.token);
    }
    /// Returns a correctly-typed pointer to the `Io.Group.state` field. The double-pointer here is
    /// intentional, because the `state` field itself stores a pointer, and this function returns a
    /// pointer to that field.
    ///
    /// On completion of the whole group, if `status` indicates that there is an awaiter, the last
    /// task must increment this `u32` and do a futex wake on it to signal that awaiter.
    fn awaiter(g: Group) **std.atomic.Value(u32) {
        return @ptrCast(&g.ptr.state);
    }

    const Status = packed struct(usize) {
        num_running: @Int(.unsigned, @bitSizeOf(usize) - 2),
        have_awaiter: bool,
        canceled: bool,
    };

    const Task = struct {
        runnable: Runnable,
        group: *Io.Group,
        func: *const fn (context: *const anyopaque) void,
        context_alignment: Alignment,
        alloc_len: usize,

        /// `Task.runnable.node` is `undefined` in the created `Task`.
        fn create(
            gpa: Allocator,
            group: Group,
            context: []const u8,
            context_alignment: Alignment,
            func: *const fn (context: *const anyopaque) void,
        ) Allocator.Error!*Task {
            const max_context_misalignment = context_alignment.toByteUnits() -| @alignOf(Task);
            const worst_case_context_offset = context_alignment.forward(@sizeOf(Task) + max_context_misalignment);
            const alloc_len = worst_case_context_offset + context.len;

            const task: *Task = @ptrCast(@alignCast(try gpa.alignedAlloc(u8, .of(Task), alloc_len)));
            errdefer comptime unreachable;

            task.* = .{
                .runnable = .{
                    .node = undefined,
                    .startFn = &start,
                },
                .group = group.ptr,
                .func = func,
                .context_alignment = context_alignment,
                .alloc_len = alloc_len,
            };
            @memcpy(task.contextPointer()[0..context.len], context);
            return task;
        }

        fn destroy(task: *Task, gpa: Allocator) void {
            const base: [*]align(@alignOf(Task)) u8 = @ptrCast(task);
            gpa.free(base[0..task.alloc_len]);
        }

        fn contextPointer(task: *Task) [*]u8 {
            const base: [*]u8 = @ptrCast(task);
            const offset = task.context_alignment.forward(@intFromPtr(base) + @sizeOf(Task)) - @intFromPtr(base);
            return base + offset;
        }

        pub fn start(r: *Runnable, thread: *Thread, t: *Threaded) void {
            const task: *Task = @fieldParentPtr("runnable", r);
            const group: Group = .{ .ptr = task.group };

            // This would be a simple store, but it's upgraded to an RMW so we can use `.acquire` to
            // enforce the ordering between this and the `group.status().load` below. Paired with
            // the `.release` rmw on `Thread.status` in `cancelThreads`, this creates a StoreLoad
            // barrier which guarantees that when a group is canceled, either we see the cancelation
            // in the group status, or the canceler sees our thread status so can directly notify us
            // of the cancelation.
            _ = thread.status.swap(.{
                .cancelation = .none,
                .awaitable = .fromGroup(group.ptr),
            }, .acquire);
            if (group.status().load(.monotonic).canceled) {
                thread.status.store(.{
                    .cancelation = .canceling,
                    .awaitable = .fromGroup(group.ptr),
                }, .monotonic);
            }

            task.func(task.contextPointer());

            thread.status.store(.{ .cancelation = .none, .awaitable = .null }, .monotonic);
            const old_status = group.status().fetchSub(.{
                .num_running = 1,
                .have_awaiter = false,
                .canceled = false,
            }, .acq_rel); // acquire `group.awaiter()`, release task results
            assert(old_status.num_running > 0);
            if (old_status.have_awaiter and old_status.num_running == 1) {
                const to_signal = group.awaiter().*;
                // `awaiter` should only be modified by us. For another thread to see `num_running`
                // drop to 0 after this point would indicate that another task started up, meaning
                // `async`/`cancel` was racing with awaited group completion.
                group.awaiter().* = undefined;
                _ = to_signal.fetchAdd(1, .release); // release results
                Thread.futexWake(&to_signal.raw, 1);
            }

            // Task completed. Self-destruct sequence initiated.
            task.destroy(t.allocator);
        }
    };

    /// Assumes the caller has already atomically updated the group status to indicate cancelation,
    /// and notifies any already-running threads of this cancelation.
    fn cancelThreads(g: Group, t: *Threaded) bool {
        var any_blocked = false;
        var it = t.worker_threads.load(.acquire); // acquire `Thread` values
        while (it) |thread| : (it = thread.next) {
            // This non-mutating RMW exists for ordering reasons: see comment in `Group.Task.start` for reasons.
            _ = thread.status.fetchOr(.{ .cancelation = @fromBackingInt(@intCast(0)), .awaitable = .null }, .release);
            if (thread.cancelAwaitable(.fromGroup(g.ptr))) any_blocked = true;
        }
        return any_blocked;
    }

    /// Uses `Thread.signalCanceledSyscall` to signal any threads which are still blocked in a
    /// syscall for this group and have not observed a cancelation request yet. Returns `true` if
    /// more signals may be necessary, in which case the caller must call this again after a delay.
    fn signalAllCanceledSyscalls(g: Group, t: *Threaded) bool {
        var any_signaled = false;
        var it = t.worker_threads.load(.acquire); // acquire `Thread` values
        while (it) |thread| : (it = thread.next) {
            if (thread.signalCanceledSyscall(t, .fromGroup(g.ptr))) any_signaled = true;
        }
        return any_signaled;
    }

    /// The caller has canceled `g`. Inform any threads working on that group of the cancelation if
    /// necessary, and wait for `g` to finish (indicated by `num_completed` being incremented from 0
    /// to 1), while sending regular signals to threads if necessary for them to unblock from any
    /// cancelable syscalls.
    ///
    /// `skip_signals` means it is already known that no threads are currently working on the group
    /// so no notifications or signals are necessary.
    fn waitForCancelWithSignaling(
        g: Group,
        t: *Threaded,
        num_completed: *std.atomic.Value(u32),
        skip_signals: bool,
    ) void {
        var need_signal: bool = !skip_signals and g.cancelThreads(t);
        var timeout_ns: u64 = 1 << 10;
        while (true) {
            need_signal = need_signal and g.signalAllCanceledSyscalls(t);
            Thread.futexWaitUncancelable(&num_completed.raw, 0, if (need_signal) timeout_ns else null);
            switch (num_completed.load(.acquire)) { // acquire task results
                0 => {},
                1 => break,
                else => unreachable,
            }
            timeout_ns <<|= 1;
        }
    }
};

/// Trailing data:
/// 1. context
/// 2. result
const Future = struct {
    runnable: Runnable,
    func: *const fn (context: *const anyopaque, result: *anyopaque) void,
    status: std.atomic.Value(Status),
    /// On completion, increment this `u32` and do a futex wake on it.
    awaiter: *std.atomic.Value(u32),
    context_alignment: Alignment,
    result_offset: usize,
    alloc_len: usize,

    const Status = packed struct(usize) {
        /// The values of this enum are chosen so that await/cancel can just OR with 0b01 and 0b11
        /// respectively. That *does* clobber `.done`, but that's actually fine, because if the tag
        /// is `.done` then only the awaiter is referencing this `Future` anyway.
        tag: enum(u2) {
            /// The future is queued or running (depending on whether `thread` is set).
            pending = 0b00,
            /// Like `pending`, but the future is being awaited. `Future.awaiter` is populated.
            pending_awaited = 0b01,
            /// Like `pending`, but the future is being canceled. `Future.awaiter` is populated.
            pending_canceled = 0b11,
            /// The future has already completed. `thread` is `.null`, unless the future terminated
            /// with an acknowledged cancel request, in which case `thread` is `.all_ones`.
            done = 0b10,
        },
        /// When the future begins execution, this is atomically updated from `null` to the thread running the
        /// `Future`, so that cancelation knows which thread to cancel.
        thread: Thread.PackedPtr,
    };

    /// `Future.runnable.node` is `undefined` in the created `Future`.
    fn create(
        gpa: Allocator,
        result_len: usize,
        result_alignment: Alignment,
        context: []const u8,
        context_alignment: Alignment,
        func: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) Allocator.Error!*Future {
        const max_context_misalignment = context_alignment.toByteUnits() -| @alignOf(Future);
        const worst_case_context_offset = context_alignment.forward(@sizeOf(Future) + max_context_misalignment);
        const worst_case_result_offset = result_alignment.forward(worst_case_context_offset + context.len);
        const alloc_len = worst_case_result_offset + result_len;

        const future: *Future = @ptrCast(@alignCast(try gpa.alignedAlloc(u8, .of(Future), alloc_len)));
        errdefer comptime unreachable;

        const actual_context_addr = context_alignment.forward(@intFromPtr(future) + @sizeOf(Future));
        const actual_result_addr = result_alignment.forward(actual_context_addr + context.len);
        const actual_result_offset = actual_result_addr - @intFromPtr(future);
        future.* = .{
            .runnable = .{
                .node = undefined,
                .startFn = &start,
            },
            .func = func,
            .status = .init(.{
                .tag = .pending,
                .thread = .null,
            }),
            .awaiter = undefined,
            .context_alignment = context_alignment,
            .result_offset = actual_result_offset,
            .alloc_len = alloc_len,
        };
        @memcpy(future.contextPointer()[0..context.len], context);
        return future;
    }

    fn destroy(future: *Future, gpa: Allocator) void {
        const base: [*]align(@alignOf(Future)) u8 = @ptrCast(future);
        gpa.free(base[0..future.alloc_len]);
    }

    fn resultPointer(future: *Future) [*]u8 {
        const base: [*]u8 = @ptrCast(future);
        return base + future.result_offset;
    }

    fn contextPointer(future: *Future) [*]u8 {
        const base: [*]u8 = @ptrCast(future);
        const context_offset = future.context_alignment.forward(@intFromPtr(future) + @sizeOf(Future)) - @intFromPtr(future);
        return base + context_offset;
    }

    pub fn start(r: *Runnable, thread: *Thread, t: *Threaded) void {
        _ = t;
        const future: *Future = @fieldParentPtr("runnable", r);

        thread.status.store(.{
            .cancelation = .none,
            .awaitable = .fromFuture(future),
        }, .monotonic);
        {
            const old_status = future.status.fetchOr(.{
                .tag = .pending,
                .thread = .pack(thread),
            }, .release);
            assert(old_status.thread == .null);
            switch (old_status.tag) {
                .pending, .pending_awaited => {},
                .pending_canceled => thread.status.store(.{
                    .cancelation = .canceling,
                    .awaitable = .fromFuture(future),
                }, .monotonic),
                .done => unreachable,
            }
        }

        future.func(future.contextPointer(), future.resultPointer());

        const had_acknowledged_cancel = switch (thread.status.load(.monotonic).cancelation) {
            .none, .canceling => false,
            .canceled => true,
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_alertable => unreachable,
            .blocked_alertable_canceling => unreachable,
            .blocked_canceling => unreachable,
        };
        thread.status.store(.{ .cancelation = .none, .awaitable = .null }, .monotonic);
        const old_status = future.status.swap(.{
            .tag = .done,
            .thread = if (had_acknowledged_cancel) .all_ones else .null,
        }, .acq_rel); // acquire `future.awaiter`, release results
        switch (old_status.tag) {
            .pending => {},
            .pending_awaited, .pending_canceled => {
                const to_signal = future.awaiter;
                _ = to_signal.fetchAdd(1, .release); // release results
                Thread.futexWake(&to_signal.raw, 1);
            },
            .done => unreachable,
        }
    }

    /// The caller has canceled `future`. `thread` is the thread currently running that future.
    /// Inform `thread` of the cancelation if necessary, and wait for `future` to finish (indicated
    /// by `num_completed` being incremented from 0 to 1), while sending regular signals to `thread`
    /// if necessary for it to unblock from a cancelable syscall.
    fn waitForCancelWithSignaling(
        future: *Future,
        t: *Threaded,
        num_completed: *std.atomic.Value(u32),
        thread: ?*Thread,
    ) void {
        var need_signal: bool = if (thread) |th| th.cancelAwaitable(.fromFuture(future)) else false;
        var timeout_ns: u64 = 1 << 10;
        while (true) {
            need_signal = need_signal and thread.?.signalCanceledSyscall(t, .fromFuture(future));
            Thread.futexWaitUncancelable(&num_completed.raw, 0, if (need_signal) timeout_ns else null);
            switch (num_completed.load(.acquire)) { // acquire task results
                0 => {},
                1 => break,
                else => unreachable,
            }
            timeout_ns <<|= 1;
        }
    }
};

/// A sequence of (ptr_bit_width - 3) bits which uniquely identifies a group or future. The bits are
/// the MSBs of the `*Io.Group` or `*Future`. These things do not necessarily have 3 zero bits at
/// the end (they are pointer-aligned, so on 32-bit targets only have 2), but because they both have
/// a *size* of at least 8 bytes, no two groups/futures in memory at the same time will have the
/// same value for all of these bits. In other words, given a group/future pointer, the next group
/// or future must be at least 8 bytes later, so its address will have a different value for one of
/// the top (ptr_bit_width - 3) bits.
const AwaitableId = enum(@Int(.unsigned, @bitSizeOf(usize) - 3)) {
    comptime {
        assert(@sizeOf(Future) >= 8);
        assert(@sizeOf(Io.Group) >= 8);
    }
    null = 0,
    all_ones = std.math.maxInt(@Int(.unsigned, @bitSizeOf(usize) - 3)),
    _,
    const Split = packed struct(usize) { low: u3, high: AwaitableId };
    fn fromGroup(g: *Io.Group) AwaitableId {
        const split: Split = @bitCast(@intFromPtr(g));
        return split.high;
    }
    fn fromFuture(f: *Future) AwaitableId {
        const split: Split = @bitCast(@intFromPtr(f));
        return split.high;
    }
};

pub const Thread = struct {
    next: ?*Thread,

    id: std.Thread.Id,
    handle: Handle,

    status: std.atomic.Value(Status),

    cancel_protection: Io.CancelProtection,
    /// Always released when `Status.cancelation` is set to `.parked`.
    futex_waiter: if (use_parking_futex) ?*parking_futex.Waiter else ?noreturn,
    unpark_flag: UnparkFlag,
    park_tid: if (ParkTid == std.Thread.Id) void else ParkTid,

    csprng: Csprng,

    pub const Handle = Handle: {
        if (std.Thread.use_pthreads) break :Handle std.c.pthread_t;
        if (is_windows) break :Handle windows.HANDLE;
        break :Handle void;
    };

    const Status = packed struct(usize) {
        /// The specific values of these enum fields are chosen to simplify the implementation of
        /// the transformations we need to apply to this state.
        cancelation: enum(u3) {
            /// The thread has not yet been canceled, and is not in a cancelable operation.
            /// To request cancelation, just set the status to `.canceling`.
            none = 0b000,

            /// The thread is parked in a cancelable futex wait or sleep.
            /// Only applicable if `use_parking_futex` or `use_parking_sleep`.
            /// To request cancelation, set the status to `.canceling` and unpark the thread.
            /// To unpark for another reason (futex wake), set the status to `.none` and unpark the thread.
            parked = 0b001,

            /// The thread is blocked in a cancelable system call.
            /// To request cancelation, set the status to `.blocked_canceling` and repeatedly interrupt the system call until the status changes.
            blocked = 0b011,

            /// Windows-only: the thread is blocked in an alertable wait via
            /// `NtDelayExecution`. To request cancelation, set the status to
            /// `blocked_alertable_canceling` and repeatedly alert the thread
            /// until the status changes.
            blocked_alertable = 0b010,

            /// The thread has an outstanding cancelation request but is not in a cancelable operation.
            /// When it acknowledges the cancelation, it will set the status to `.canceled`.
            canceling = 0b110,

            /// The thread has received and acknowledged a cancelation request.
            /// If `recancel` is called, the status will revert to `.canceling`, but otherwise, the status
            /// will not change for the remainder of this task's execution.
            canceled = 0b111,

            /// The thread is blocked in a cancelable system call, and is being
            /// canceled. The thread which triggered the cancelation will send
            /// signals to this thread until its status changes.
            blocked_canceling = 0b101,

            /// Windows-only: the thread is blocked in an alertable wait via
            /// `NtDelayExecution`, and is being canceled. The thread which
            /// triggered the cancelation will send signals to this thread
            /// until its status changes.
            blocked_alertable_canceling = 0b100,
        },

        /// We cannot turn this value back into a pointer. Instead, it exists so that a task can be
        /// canceled by a cmpxchg on thread status: if it is running the task we want to cancel,
        /// then update the `cancelation` field.
        awaitable: AwaitableId,
    };

    const SignaleeId = if (std.Thread.use_pthreads) std.c.pthread_t else std.Thread.Id;

    pub threadlocal var current: ?*Thread = null;

    /// A value that does not alias any other thread id.
    const invalid_id: std.Thread.Id = std.math.maxInt(std.Thread.Id);

    fn currentId() std.Thread.Id {
        return if (current) |t| t.id else std.Thread.getCurrentId();
    }

    /// The thread is neither in a syscall nor entering one, but we want to check for cancelation
    /// anyway. If there is a pending cancel request, acknowledge it and return `error.Canceled`.
    pub fn checkCancel() Io.Cancelable!void {
        const thread = Thread.current orelse return;
        switch (thread.cancel_protection) {
            .blocked => return,
            .unblocked => {},
        }
        // Here, unlike `Syscall.checkCancel`, it's not particularly likely that we're canceled, so
        // it seems preferable to do a cheap atomic load and, in the unlikely case, a separate store
        // to acknowledge. Besides, the state transitions we need here can't be done with one atomic
        // OR/AND/XOR on `Status.cancelation`, so we don't actually have any other option.
        const status = thread.status.load(.monotonic);
        switch (status.cancelation) {
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_alertable => unreachable,
            .blocked_alertable_canceling => unreachable,
            .blocked_canceling => unreachable,
            .none, .canceled => {},
            .canceling => {
                thread.status.store(.{
                    .cancelation = .canceled,
                    .awaitable = status.awaitable,
                }, .monotonic);
                return error.Canceled;
            },
        }
    }

    fn futexWaitUncancelable(ptr: *const u32, expect: u32, timeout_ns: ?u64) void {
        return Thread.futexWaitInner(ptr, expect, true, timeout_ns) catch unreachable;
    }

    fn futexWait(ptr: *const u32, expect: u32, timeout_ns: ?u64) Io.Cancelable!void {
        return Thread.futexWaitInner(ptr, expect, false, timeout_ns);
    }

    fn futexWaitInner(ptr: *const u32, expect: u32, uncancelable: bool, timeout_ns: ?u64) Io.Cancelable!void {
        @branchHint(.cold);

        if (builtin.single_threaded) unreachable; // nobody would ever wake us

        if (use_parking_futex) {
            return parking_futex.wait(
                ptr,
                expect,
                uncancelable,
                if (timeout_ns) |ns| .{ .duration = .{
                    .raw = .fromNanoseconds(ns),
                    .clock = .boot,
                } } else .none,
            );
        } else if (builtin.cpu.arch.isWasm()) {
            comptime assert(builtin.cpu.has(.wasm, .atomics));
            // TODO implement cancelation for WASM futex waits by signaling the futex
            if (!uncancelable) try Thread.checkCancel();
            const to: i64 = if (timeout_ns) |ns| std.math.cast(i64, ns) orelse std.math.maxInt(i64) else -1;
            const signed_expect: i32 = @bitCast(expect);
            const result = asm volatile (
                \\local.get %[ptr]
                \\local.get %[expected]
                \\local.get %[timeout]
                \\memory.atomic.wait32 0
                \\local.set %[ret]
                : [ret] "=r" (-> u32),
                : [ptr] "r" (ptr),
                  [expected] "r" (signed_expect),
                  [timeout] "r" (to),
            );
            switch (result) {
                0 => {}, // ok
                1 => {}, // expected != loaded
                2 => {}, // timeout
                else => assert(!is_debug),
            }
        } else switch (native_os) {
            .linux => {
                const linux = std.os.linux;
                var ts_buffer: linux.timespec = undefined;
                const ts: ?*linux.timespec = if (timeout_ns) |ns| ts: {
                    ts_buffer = timestampToPosix(ns);
                    break :ts &ts_buffer;
                } else null;
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = linux.futex_4arg(ptr, .{ .cmd = .WAIT, .private = true }, expect, ts);
                syscall.finish();
                switch (linux.errno(rc)) {
                    .SUCCESS => {}, // notified by `wake()`
                    .INTR => {}, // caller's responsibility to retry
                    .AGAIN => {}, // ptr.* != expect
                    .INVAL => {}, // possibly timeout overflow
                    .TIMEDOUT => {},
                    .FAULT => recoverableOsBugDetected(), // ptr was invalid
                    else => recoverableOsBugDetected(),
                }
            },
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
                const c = std.c;
                const flags: c.UL = .{
                    .op = .COMPARE_AND_WAIT,
                    .NO_ERRNO = true,
                };
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const status = switch (darwin_impl.darwin_supports_ulock_wait2) {
                    true => c.__ulock_wait2(flags, ptr, expect, ns: {
                        const ns = timeout_ns orelse break :ns 0;
                        if (ns == 0) break :ns 1;
                        break :ns ns;
                    }, 0),
                    false => c.__ulock_wait(flags, ptr, expect, us: {
                        const ns = timeout_ns orelse break :us 0;
                        const us = std.math.lossyCast(u32, ns / std.time.ns_per_us);
                        if (us == 0) break :us 1;
                        break :us us;
                    }),
                };
                syscall.finish();
                if (status >= 0) return;
                switch (@as(c.E, @fromBackingInt(@intCast(-status)))) {
                    .INTR => {}, // spurious wake
                    // Address of the futex was paged out. This is unlikely, but possible in theory, and
                    // pthread/libdispatch on darwin bother to handle it. In this case we'll return
                    // without waiting, but the caller should retry anyway.
                    .FAULT => {},
                    .TIMEDOUT => {}, // timeout
                    else => recoverableOsBugDetected(),
                }
            },
            .freebsd => {
                const flags = @backingInt(std.c.UMTX_OP.WAIT_UINT_PRIVATE);
                var tm_size: usize = 0;
                var tm: std.c._umtx_time = undefined;
                var tm_ptr: ?*const std.c._umtx_time = null;
                if (timeout_ns) |ns| {
                    tm_ptr = &tm;
                    tm_size = @sizeOf(@TypeOf(tm));
                    tm.flags = 0; // use relative time not UMTX_ABSTIME
                    tm.clockid = .MONOTONIC;
                    tm.timeout = timestampToPosix(ns);
                }
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = std.c._umtx_op(@intFromPtr(ptr), flags, @as(c_ulong, expect), tm_size, @intFromPtr(tm_ptr));
                syscall.finish();
                if (is_debug) switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .FAULT => unreachable, // one of the args points to invalid memory
                    .INVAL => unreachable, // arguments should be correct
                    .TIMEDOUT => {}, // timeout
                    .INTR => {}, // spurious wake
                    else => unreachable,
                };
            },
            .openbsd => {
                var tm: std.c.timespec = undefined;
                var tm_ptr: ?*const std.c.timespec = null;
                if (timeout_ns) |ns| {
                    tm_ptr = &tm;
                    tm = timestampToPosix(ns);
                }
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = std.c.futex(
                    ptr,
                    std.c.FUTEX.WAIT | std.c.FUTEX.PRIVATE_FLAG,
                    @as(c_int, @bitCast(expect)),
                    tm_ptr,
                    null, // uaddr2 is ignored
                );
                syscall.finish();
                if (is_debug) switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .NOSYS => unreachable, // constant op known good value
                    .AGAIN => {}, // contents of uaddr != val
                    .INVAL => unreachable, // invalid timeout
                    .TIMEDOUT => {}, // timeout
                    .INTR => {}, // a signal arrived
                    .CANCELED => {}, // a signal arrived and SA_RESTART was set
                    else => unreachable,
                };
            },
            .dragonfly => {
                var timeout_us: c_int = undefined;
                if (timeout_ns) |ns| {
                    timeout_us = std.math.cast(c_int, ns / std.time.ns_per_us) orelse std.math.maxInt(c_int);
                } else {
                    timeout_us = 0;
                }
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = std.c.umtx_sleep(@ptrCast(ptr), @bitCast(expect), timeout_us);
                syscall.finish();
                if (is_debug) switch (std.posix.errno(rc)) {
                    .SUCCESS => {},
                    .BUSY => {}, // ptr != expect
                    .AGAIN => {}, // maybe timed out, or paged out, or hit 2s kernel refresh
                    .INTR => {}, // spurious wake
                    .INVAL => unreachable, // invalid timeout
                    else => unreachable,
                };
            },
            .serenity => {
                var tm: std.c.timespec = undefined;
                var tm_ptr: ?*const std.c.timespec = null;
                if (timeout_ns) |ns| {
                    tm_ptr = &tm;
                    tm = timestampToPosix(ns);
                }
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = std.c.futex(
                    @constCast(ptr),
                    std.c.FUTEX.WAIT | std.c.FUTEX.PRIVATE_FLAG,
                    expect,
                    tm_ptr,
                    null,
                    0,
                );
                syscall.finish();
                if (is_debug) switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .AGAIN => {}, // ptr != expect
                    .TIMEDOUT => {}, // timeout
                    .FAULT => unreachable, // ptr was invalid
                    .INVAL => unreachable, // ptr was misaligned
                    .NOMEM => {}, // OOM, treat as spurious wake
                    else => unreachable,
                };
            },
            else => @compileError("unimplemented: futexWait"),
        }
    }

    fn futexWake(ptr: *const u32, max_waiters: u32) void {
        @branchHint(.cold);
        assert(max_waiters != 0);

        if (builtin.single_threaded) return; // nothing to wake up

        if (use_parking_futex) {
            return parking_futex.wake(ptr, max_waiters);
        } else if (builtin.cpu.arch.isWasm()) {
            comptime assert(builtin.cpu.has(.wasm, .atomics));
            const woken_count = asm volatile (
                \\local.get %[ptr]
                \\local.get %[waiters]
                \\memory.atomic.notify 0
                \\local.set %[ret]
                : [ret] "=r" (-> u32),
                : [ptr] "r" (ptr),
                  [waiters] "r" (max_waiters),
            );
            _ = woken_count; // can be 0 when linker flag 'shared-memory' is not enabled
        } else switch (native_os) {
            .linux => {
                const linux = std.os.linux;
                switch (linux.errno(linux.futex_3arg(
                    ptr,
                    .{ .cmd = .WAKE, .private = true },
                    @min(max_waiters, std.math.maxInt(i32)),
                ))) {
                    .SUCCESS => return, // successful wake up
                    .INVAL => return, // invalid futex_wait() on ptr done elsewhere
                    .FAULT => return, // pointer became invalid while doing the wake
                    else => return recoverableOsBugDetected(), // deadlock due to operating system bug
                }
            },
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
                const c = std.c;
                const flags: c.UL = .{
                    .op = .COMPARE_AND_WAIT,
                    .NO_ERRNO = true,
                    .WAKE_ALL = max_waiters > 1,
                };
                while (true) {
                    const status = c.__ulock_wake(flags, ptr, 0);
                    if (status >= 0) return;
                    switch (@as(c.E, @fromBackingInt(@intCast(-status)))) {
                        .INTR, .CANCELED => continue, // spurious wake()
                        .FAULT => unreachable, // __ulock_wake doesn't generate EFAULT according to darwin pthread_cond_t
                        .NOENT => return, // nothing was woken up
                        .ALREADY => unreachable, // only for UL.Op.WAKE_THREAD
                        else => unreachable, // deadlock due to operating system bug
                    }
                }
            },
            .freebsd => {
                const rc = std.c._umtx_op(
                    @intFromPtr(ptr),
                    @backingInt(std.c.UMTX_OP.WAKE_PRIVATE),
                    @as(c_ulong, @min(max_waiters, std.math.maxInt(c_int))),
                    0, // there is no timeout struct
                    0, // there is no timeout struct pointer
                );
                if (is_debug) switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .FAULT => {}, // it's ok if the ptr doesn't point to valid memory
                    .INVAL => unreachable, // arguments should be correct
                    else => unreachable, // deadlock due to operating system bug
                };
            },
            .openbsd => {
                const rc = std.c.futex(
                    ptr,
                    std.c.FUTEX.WAKE | std.c.FUTEX.PRIVATE_FLAG,
                    @min(max_waiters, std.math.maxInt(c_int)),
                    null, // timeout is ignored
                    null, // uaddr2 is ignored
                );
                assert(rc >= 0);
            },
            .dragonfly => {
                // will generally return 0 unless the address is bad
                _ = std.c.umtx_wakeup(
                    @ptrCast(ptr),
                    @min(max_waiters, std.math.maxInt(c_int)),
                );
            },
            .serenity => {
                const rc = std.c.futex(
                    @constCast(ptr),
                    std.c.FUTEX.WAKE | std.c.FUTEX.PRIVATE_FLAG,
                    max_waiters,
                    null,
                    null,
                    0,
                );
                if (is_debug) switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .FAULT => {}, // it's ok if the ptr doesn't point to valid memory
                    .INVAL => unreachable, // arguments should be correct
                    else => unreachable,
                };
            },
            else => @compileError("unimplemented: futexWake"),
        }
    }

    /// Cancels `thread` if it is working on `awaitable`.
    ///
    /// It is possible that `thread` gets canceled by this function, but is blocked in a syscall. In
    /// that case, the thread may need to be sent a signal to interrupt the call. This function will
    /// return `true` to indicate this, in which case the caller must call `signalCanceledSyscall`.
    fn cancelAwaitable(thread: *Thread, awaitable: AwaitableId) bool {
        var status = thread.status.load(.monotonic);
        while (true) {
            if (status.awaitable != awaitable) return false; // thread is working on something else
            status = switch (status.cancelation) {
                .none => thread.status.cmpxchgWeak(
                    .{ .cancelation = .none, .awaitable = awaitable },
                    .{ .cancelation = .canceling, .awaitable = awaitable },
                    .monotonic,
                    .monotonic,
                ) orelse return false,

                .parked => thread.status.cmpxchgWeak(
                    .{ .cancelation = .parked, .awaitable = awaitable },
                    .{ .cancelation = .canceling, .awaitable = awaitable },
                    .acquire, // acquire `thread.futex_waiter`
                    .monotonic,
                ) orelse {
                    if (!use_parking_futex and !use_parking_sleep) unreachable;
                    if (thread.futex_waiter) |futex_waiter| {
                        parking_futex.removeCanceledWaiter(futex_waiter);
                    }
                    if (need_unpark_flag) setUnparkFlag(&thread.unpark_flag);
                    unpark(&.{if (ParkTid == std.Thread.Id) thread.id else thread.park_tid}, null);
                    return false;
                },

                .blocked => thread.status.cmpxchgWeak(
                    .{ .cancelation = .blocked, .awaitable = awaitable },
                    .{ .cancelation = .blocked_canceling, .awaitable = awaitable },
                    .monotonic,
                    .monotonic,
                ) orelse return true,

                .blocked_alertable => thread.status.cmpxchgWeak(
                    .{ .cancelation = .blocked_alertable, .awaitable = awaitable },
                    .{ .cancelation = .blocked_alertable_canceling, .awaitable = awaitable },
                    .monotonic,
                    .monotonic,
                ) orelse {
                    if (!is_windows) unreachable;
                    return true;
                },

                .canceling, .canceled => {
                    // This can happen when the task start raced with the cancelation, so the thread
                    // saw the cancelation on the future/group *and* we are trying to signal the
                    // thread here.
                    return false;
                },

                .blocked_canceling => unreachable, // `awaitable` has not been canceled before now
                .blocked_alertable_canceling => unreachable, // `awaitable` has not been canceled before now
            };
        }
    }

    /// Sends a signal to `thread` if it is still blocked in a syscall (i.e. has not yet observed
    /// the cancelation request from `cancelAwaitable`).
    ///
    /// Unfortunately, the signal could arrive before the syscall actually starts, so the interrupt
    /// is missed. To handle this, we may need to send multiple signals. As such, if this function
    /// returns `true`, then it should be called again after a short delay to send another signal if
    /// the thread is still blocked. For the implementation, `Future.waitForCancelWithSignaling` and
    /// `Group.waitForCancelWithSignaling`: they use exponential backoff starting at a 1us delay and
    /// doubling each call. In practice, it is rare to send more than one signal.
    fn signalCanceledSyscall(thread: *Thread, t: *Threaded, awaitable: AwaitableId) bool {
        const status = thread.status.load(.monotonic);
        if (status.awaitable != awaitable) {
            // The thread has moved on and is working on something totally different.
            return false;
        }

        // The thread ID and/or handle can be read non-atomically because they never change and were
        // released by the store that made `thread` available to us.

        switch (status.cancelation) {
            .blocked_canceling => if (std.Thread.use_pthreads) {
                return switch (std.c.pthread_kill(thread.handle, .IO)) {
                    0 => true,
                    else => false,
                };
            } else switch (native_os) {
                .linux => {
                    const pid: posix.pid_t = pid: {
                        const cached_pid = @atomicLoad(Pid, &t.pid, .monotonic);
                        if (cached_pid != .unknown) break :pid @backingInt(cached_pid);
                        const pid = std.os.linux.getpid();
                        @atomicStore(Pid, &t.pid, @fromBackingInt(@intCast(pid)), .monotonic);
                        break :pid pid;
                    };
                    return switch (std.os.linux.tgkill(pid, @bitCast(thread.id), .IO)) {
                        0 => true,
                        else => false,
                    };
                },
                .windows => {
                    var iosb: windows.IO_STATUS_BLOCK = undefined;
                    return switch (windows.ntdll.NtCancelSynchronousIoFile(thread.handle, null, &iosb)) {
                        .NOT_FOUND => true, // this might mean the operation hasn't started yet
                        .SUCCESS => false, // the OS confirmed that our cancelation worked
                        else => false,
                    };
                },
                else => return false,
            },

            .blocked_alertable_canceling => {
                if (!is_windows) unreachable;
                return switch (windows.ntdll.NtAlertThread(thread.handle)) {
                    .SUCCESS => true,
                    else => false,
                };
            },

            else => {
                // The thread is working on `awaitable`, but no longer needs signaling (they already
                // woke up and saw the cancelation).
                return false;
            },
        }
    }

    /// Like a `*Thread`, but 2 bits smaller than a pointer (because the LSBs are always 0 due to
    /// alignment) so that those two bits can be used in a `packed struct`.
    const PackedPtr = enum(@Int(.unsigned, @bitSizeOf(usize) - 2)) {
        null = 0,
        all_ones = std.math.maxInt(@Int(.unsigned, @bitSizeOf(usize) - 2)),
        _,

        const Split = packed struct(usize) { low: u2, high: PackedPtr };
        fn pack(ptr: *Thread) PackedPtr {
            const split: Split = @bitCast(@intFromPtr(ptr));
            assert(split.low == 0);
            return split.high;
        }
        fn unpack(ptr: PackedPtr) ?*Thread {
            const split: Split = .{ .low = 0, .high = ptr };
            return @ptrFromInt(@as(usize, @bitCast(split)));
        }
    };
};

pub const Syscall = struct {
    thread: ?*Thread,
    /// Marks entry to a syscall region. This should be tightly scoped around the actual syscall
    /// to minimize races. The syscall must be marked as "finished" by `checkCancel`, `finish`,
    /// or one of the wrappers of `finish`.
    pub fn start() Io.Cancelable!Syscall {
        const thread = Thread.current orelse return .{ .thread = null };
        switch (thread.cancel_protection) {
            .blocked => return .{ .thread = null },
            .unblocked => {},
        }
        switch (thread.status.fetchOr(.{
            .cancelation = @fromBackingInt(@intCast(0b011)),
            .awaitable = .null,
        }, .monotonic).cancelation) {
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_alertable => unreachable,
            .blocked_alertable_canceling => unreachable,
            .blocked_canceling => unreachable,
            .none => return .{ .thread = thread }, // new status is `.blocked`
            .canceling => return error.Canceled, // new status is `.canceled`
            .canceled => return .{ .thread = null }, // new status is `.canceled` (unchanged)
        }
    }
    /// Checks whether this syscall has been canceled. This should be called when a syscall is
    /// interrupted through a mechanism which may indicate cancelation, or may be spurious. If
    /// the syscall was canceled, it is finished and `error.Canceled` is returned. Otherwise,
    /// the syscall is not marked finished, and the caller should retry.
    pub fn checkCancel(s: Syscall) Io.Cancelable!void {
        const thread = s.thread orelse return;
        switch (thread.status.fetchOr(.{
            .cancelation = @fromBackingInt(@intCast(0b010)),
            .awaitable = .null,
        }, .monotonic).cancelation) {
            .none => unreachable,
            .parked => unreachable,
            .blocked_alertable => unreachable,
            .blocked_alertable_canceling => unreachable,
            .canceling => unreachable,
            .canceled => unreachable,
            .blocked => {}, // new status is `.blocked` (unchanged)
            .blocked_canceling => return error.Canceled, // new status is `.canceled`
        }
    }
    /// Marks this syscall as finished.
    pub fn finish(s: Syscall) void {
        const thread = s.thread orelse return;
        switch (thread.status.fetchXor(.{
            .cancelation = @fromBackingInt(@intCast(0b011)),
            .awaitable = .null,
        }, .monotonic).cancelation) {
            .none => unreachable,
            .parked => unreachable,
            .blocked_alertable => unreachable,
            .blocked_alertable_canceling => unreachable,
            .canceling => unreachable,
            .canceled => unreachable,
            .blocked => {}, // new status is `.none`
            .blocked_canceling => {}, // new status is `.canceling`
        }
    }
    /// Indicates instead of `NtCancelSynchronousIoFile` we need to use
    /// `NtAlertThread` to interrupt the wait.
    ///
    /// Windows only, called from blocked state only.
    fn toAlertable(s: Syscall) Io.Cancelable!AlertableSyscall {
        comptime assert(is_windows);
        const thread = s.thread orelse return .{ .thread = null };
        var prev = thread.status.load(.monotonic);
        while (true) prev = switch (prev.cancelation) {
            .none => unreachable,
            .parked => unreachable,
            .blocked_alertable => unreachable,
            .blocked_alertable_canceling => unreachable,
            .canceling => unreachable,
            .canceled => unreachable,

            .blocked => thread.status.cmpxchgWeak(prev, .{
                .cancelation = .blocked_alertable,
                .awaitable = prev.awaitable,
            }, .monotonic, .monotonic) orelse return .{ .thread = thread },

            .blocked_canceling => thread.status.cmpxchgWeak(prev, .{
                .cancelation = .canceled,
                .awaitable = prev.awaitable,
            }, .monotonic, .monotonic) orelse return error.Canceled,
        };
    }
    /// Convenience wrapper which calls `finish`, then returns `err`.
    pub fn fail(s: Syscall, err: anytype) @TypeOf(err) {
        s.finish();
        return err;
    }
    /// Convenience wrapper which calls `finish`, then calls `Threaded.errnoBug`.
    pub fn errnoBug(s: Syscall, err: posix.E) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return Threaded.errnoBug(err);
    }
    /// Convenience wrapper which calls `finish`, then calls `posix.unexpectedErrno`.
    pub fn unexpectedErrno(s: Syscall, err: posix.E) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return posix.unexpectedErrno(err);
    }
    /// Convenience wrapper which calls `finish`, then calls `windows.statusBug`.
    pub fn ntstatusBug(s: Syscall, status: windows.NTSTATUS) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return windows.statusBug(status);
    }
    /// Convenience wrapper which calls `finish`, then calls `windows.unexpectedStatus`.
    pub fn unexpectedNtstatus(s: Syscall, status: windows.NTSTATUS) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return windows.unexpectedStatus(status);
    }
};

pub const AlertableSyscall = struct {
    thread: ?*Thread,

    comptime {
        assert(is_windows);
    }

    pub fn start() Io.Cancelable!AlertableSyscall {
        const thread = Thread.current orelse return .{ .thread = null };
        switch (thread.cancel_protection) {
            .blocked => return .{ .thread = null },
            .unblocked => {},
        }
        const old_status = thread.status.fetchOr(.{
            .cancelation = @fromBackingInt(@intCast(0b010)),
            .awaitable = .null,
        }, .monotonic);
        switch (old_status.cancelation) {
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_alertable => unreachable,
            .blocked_canceling => unreachable,
            .blocked_alertable_canceling => unreachable,
            .none => return .{ .thread = thread }, // new status is `.blocked_alertable`
            .canceling => {
                // Status is unchanged (still `.canceling`)---change to `.canceled` before return.
                thread.status.store(.{ .cancelation = .canceled, .awaitable = old_status.awaitable }, .monotonic);
                return error.Canceled;
            },
            .canceled => return .{ .thread = null }, // new status is `.canceled` (unchanged)
        }
    }

    pub fn checkCancel(s: AlertableSyscall) Io.Cancelable!void {
        comptime assert(is_windows);
        const thread = s.thread orelse return;
        const old_status = thread.status.fetchOr(.{
            .cancelation = @fromBackingInt(@intCast(0b010)),
            .awaitable = .null,
        }, .monotonic);
        switch (old_status.cancelation) {
            .none => unreachable,
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_canceling => unreachable,
            .canceling => unreachable,
            .canceled => unreachable,
            .blocked_alertable => {}, // new status is `.blocked_alertable` (unchanged)
            .blocked_alertable_canceling => {
                // New status is `.canceling`---change to `.canceled` before return.
                thread.status.store(.{ .cancelation = .canceled, .awaitable = old_status.awaitable }, .monotonic);
                return error.Canceled;
            },
        }
    }

    pub fn finish(s: AlertableSyscall) void {
        comptime assert(is_windows);
        const thread = s.thread orelse return;
        switch (thread.status.fetchXor(.{
            .cancelation = @fromBackingInt(@intCast(0b010)),
            .awaitable = .null,
        }, .monotonic).cancelation) {
            .none => unreachable,
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_canceling => unreachable,
            .canceling => unreachable,
            .canceled => unreachable,
            .blocked_alertable => {}, // new status is `.none`
            .blocked_alertable_canceling => {}, // new status is `.canceling`
        }
    }

    pub fn fail(s: AlertableSyscall, err: anytype) @TypeOf(err) {
        s.finish();
        return err;
    }

    pub fn ntstatusBug(s: AlertableSyscall, status: windows.NTSTATUS) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return windows.statusBug(status);
    }

    pub fn unexpectedNtstatus(s: AlertableSyscall, status: windows.NTSTATUS) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return windows.unexpectedStatus(status);
    }
};

pub fn waitForApcOrAlert() void {
    const infinite_timeout: windows.LARGE_INTEGER = std.math.minInt(windows.LARGE_INTEGER);
    _ = windows.ntdll.NtDelayExecution(.TRUE, &infinite_timeout);
}

pub const max_iovecs_len = 8;
pub const splat_buffer_size = 64;
/// Happens to be the same number that matches maximum number of handles that
/// NtWaitForMultipleObjects accepts. We use this value also for poll() on
/// posix systems.
const poll_buffer_len = 64;
pub const default_PATH = "/usr/local/bin:/bin:/usr/bin";
comptime {
    if (@TypeOf(posix.IOV_MAX) != void) assert(max_iovecs_len <= posix.IOV_MAX);
}

pub const InitOptions = struct {
    /// Affects how many bytes are memory-mapped for threads.
    stack_size: usize = std.Thread.SpawnConfig.default_stack_size,
    /// Maximum thread pool size (excluding main thread) when dispatching async
    /// tasks. Until this limit, calls to `Io.async` when all threads are busy will
    /// cause a new thread to be spawned and permanently added to the pool. After
    /// this limit, calls to `Io.async` when all threads are busy run the task
    /// immediately.
    ///
    /// Defaults to one less than the number of logical CPU cores.
    ///
    /// Protected by `Threaded.mutex` once the I/O instance is already in use. See
    /// `setAsyncLimit`.
    async_limit: ?Io.Limit = null,
    /// Maximum thread pool size (excluding main thread) for dispatching concurrent
    /// tasks. Until this limit, calls to `Io.concurrent` will increase the thread
    /// pool size.
    ///
    /// After this number, calls to `Io.concurrent` return `error.ConcurrencyUnavailable`.
    concurrent_limit: Io.Limit = .unlimited,
    /// Affects the following operations:
    /// * `processExecutablePath` on OpenBSD and Haiku.
    argv0: Argv0 = .empty,
    /// Affects the following operations:
    /// * `fileIsTty`
    /// * `processExecutablePath` on OpenBSD and Haiku (observes "PATH").
    /// * `processSpawn`, `processSpawnPath`, `processReplace`, `processReplacePath`
    environ: process.Environ = .empty,
    /// If set to `true`, `File.MemoryMap` APIs will always take the fallback path.
    disable_memory_mapping: bool = false,
};

/// Related:
/// * `init_single_threaded`
pub fn init(
    /// Must be threadsafe. Only used for the following functions:
    /// * `Io.VTable.async`
    /// * `Io.VTable.concurrent`
    /// * `Io.VTable.groupAsync`
    /// * `Io.VTable.groupConcurrent`
    /// If these functions are avoided, then `Allocator.failing` may be passed
    /// here.
    gpa: Allocator,
    options: InitOptions,
) Threaded {
    if (builtin.single_threaded) return .{
        .allocator = gpa,
        .stack_size = options.stack_size,
        .async_limit = options.async_limit orelse init_single_threaded.async_limit,
        .cpu_count_error = init_single_threaded.cpu_count_error,
        .concurrent_limit = options.concurrent_limit,
        .old_sig_io = undefined,
        .old_sig_pipe = undefined,
        .have_signal_handler = init_single_threaded.have_signal_handler,
        .argv0 = options.argv0,
        .environ_initialized = options.environ.block.isEmpty(),
        .environ = .{ .process_environ = options.environ },
        .worker_threads = init_single_threaded.worker_threads,
        .disable_memory_mapping = options.disable_memory_mapping,
    };

    const cpu_count = std.Thread.getCpuCount();

    var t: Threaded = .{
        .allocator = gpa,
        .stack_size = options.stack_size,
        .async_limit = options.async_limit orelse if (cpu_count) |n| .limited(n - 1) else |_| .nothing,
        .concurrent_limit = options.concurrent_limit,
        .cpu_count_error = if (cpu_count) |_| null else |e| e,
        .old_sig_io = undefined,
        .old_sig_pipe = undefined,
        .have_signal_handler = false,
        .argv0 = options.argv0,
        .environ_initialized = options.environ.block.isEmpty(),
        .environ = .{ .process_environ = options.environ },
        .worker_threads = .init(null),
        .disable_memory_mapping = options.disable_memory_mapping,
    };

    if (posix.Sigaction != void) {
        // This causes sending `posix.SIG.IO` to thread to interrupt blocking
        // syscalls, returning `posix.E.INTR`.
        const act: posix.Sigaction = .{
            .handler = .{ .handler = doNothingSignalHandler },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        if (have_sig_io) posix.sigaction(.IO, &act, &t.old_sig_io);
        if (have_sig_pipe) posix.sigaction(.PIPE, &act, &t.old_sig_pipe);
        t.have_signal_handler = true;
    }

    return t;
}

/// Statically initialize such that calls to `Io.VTable.concurrent` will fail
/// with `error.ConcurrencyUnavailable`.
///
/// When initialized this way:
/// * cancel requests have no effect.
/// * `deinit` is safe, but unnecessary to call.
pub const init_single_threaded: Threaded = init: {
    const env_block: process.Environ.Block = if (is_windows) .global else .empty;
    break :init .{
        .allocator = .failing,
        .stack_size = std.Thread.SpawnConfig.default_stack_size,
        .async_limit = .nothing,
        .cpu_count_error = null,
        .concurrent_limit = .nothing,
        .old_sig_io = undefined,
        .old_sig_pipe = undefined,
        .have_signal_handler = false,
        .argv0 = .empty,
        .environ_initialized = env_block.isEmpty(),
        .environ = .{ .process_environ = .{ .block = env_block } },
        .worker_threads = .init(null),
        .disable_memory_mapping = false,
    };
};

var global_single_threaded_instance: Threaded = .init_single_threaded;

/// In general, the application is responsible for choosing the `Io`
/// implementation and library code should accept an `Io` parameter rather than
/// accessing this declaration. Most code should avoid referencing this
/// declaration entirely.
///
/// However, in some cases such as debugging, it is desirable to hardcode a
/// reference to this `Io` implementation.
///
/// This instance does not support concurrency or cancelation.
pub const global_single_threaded: *Threaded = &global_single_threaded_instance;

pub fn setAsyncLimit(t: *Threaded, new_limit: Io.Limit) void {
    mutexLockUncancelable(&t.mutex);
    defer mutexUnlock(&t.mutex);
    t.async_limit = new_limit;
}

pub fn deinit(t: *Threaded) void {
    t.join();
    if (posix.Sigaction != void and t.have_signal_handler) {
        if (have_sig_io) posix.sigaction(.IO, &t.old_sig_io, null);
        if (have_sig_pipe) posix.sigaction(.PIPE, &t.old_sig_pipe, null);
    }
    t.dl.deinit();
    t.null_file.deinit();
    t.random_file.deinit();
    t.pipe_file.deinit();
    t.* = undefined;
}

fn join(t: *Threaded) void {
    if (builtin.single_threaded) return;
    {
        mutexLockUncancelable(&t.mutex);
        defer mutexUnlock(&t.mutex);
        t.join_requested = true;
    }
    condBroadcast(&t.cond);
    t.wait_group.wait();
}

fn worker(t: *Threaded) void {
    var thread: Thread = .{
        .next = undefined,
        .id = std.Thread.getCurrentId(),
        .handle = handle: {
            if (std.Thread.use_pthreads) break :handle std.c.pthread_self();
            if (is_windows) break :handle undefined; // populated below
        },
        .status = .init(.{
            .cancelation = .none,
            .awaitable = .null,
        }),
        .cancel_protection = .unblocked,
        .futex_waiter = undefined,
        .unpark_flag = unpark_flag_init,
        .park_tid = if (ParkTid == std.Thread.Id) {} else getParkTid(),
        .csprng = .uninitialized,
    };
    Thread.current = &thread;

    if (is_windows) {
        assert(windows.ntdll.NtOpenThread(
            &thread.handle,
            .{
                .SPECIFIC = .{
                    .THREAD = .{
                        .TERMINATE = true, // for `NtCancelSynchronousIoFile`
                        .ALERT = true, // for `NtAlertThread`
                    },
                },
            },
            &.{ .ObjectName = null },
            &windows.teb().ClientId,
        ) == .SUCCESS);
    }
    defer if (is_windows) {
        windows.CloseHandle(thread.handle);
    };

    {
        var head = t.worker_threads.load(.monotonic);
        while (true) {
            thread.next = head;
            head = t.worker_threads.cmpxchgWeak(
                head,
                &thread,
                .release,
                .monotonic,
            ) orelse break;
        }
    }

    defer t.wait_group.finish();

    mutexLockUncancelable(&t.mutex);
    defer mutexUnlock(&t.mutex);

    while (true) {
        while (t.run_queue.popFirst()) |runnable_node| {
            mutexUnlock(&t.mutex);
            thread.cancel_protection = .unblocked;
            const runnable: *Runnable = @fieldParentPtr("node", runnable_node);
            runnable.startFn(runnable, &thread, t);
            mutexLockUncancelable(&t.mutex);
            t.busy_count -= 1;
        }
        if (t.join_requested) break;
        condWait(&t.cond, &t.mutex);
    }
}

pub fn io(t: *Threaded) Io {
    return .{
        .userdata = t,
        .vtable = &.{
            .crashHandler = crashHandler,

            .async = async,
            .concurrent = concurrent,
            .await = await,
            .cancel = cancel,

            .groupAsync = groupAsync,
            .groupConcurrent = groupConcurrent,
            .groupAwait = groupAwait,
            .groupCancel = groupCancel,

            .recancel = recancel,
            .swapCancelProtection = swapCancelProtection,
            .checkCancel = checkCancel,

            .futexWait = futexWait,
            .futexWaitUncancelable = futexWaitUncancelable,
            .futexWake = futexWake,

            .operate = operate,
            .batchAwaitAsync = batchAwaitAsync,
            .batchAwaitConcurrent = batchAwaitConcurrent,
            .batchCancel = batchCancel,

            .dirCreateDir = dirCreateDir,
            .dirCreateDirPath = dirCreateDirPath,
            .dirCreateDirPathOpen = dirCreateDirPathOpen,
            .dirStat = dirStat,
            .dirStatFile = dirStatFile,
            .dirAccess = dirAccess,
            .dirCreateFile = dirCreateFile,
            .dirCreateFileAtomic = dirCreateFileAtomic,
            .dirOpenFile = dirOpenFile,
            .dirOpenDir = dirOpenDir,
            .dirClose = dirClose,
            .dirRead = dirRead,
            .dirRealPath = dirRealPath,
            .dirRealPathFile = dirRealPathFile,
            .dirDeleteFile = dirDeleteFile,
            .dirDeleteDir = dirDeleteDir,
            .dirRename = dirRename,
            .dirRenamePreserve = dirRenamePreserve,
            .dirSymLink = dirSymLink,
            .dirReadLink = dirReadLink,
            .dirSetOwner = dirSetOwner,
            .dirSetFileOwner = dirSetFileOwner,
            .dirSetPermissions = dirSetPermissions,
            .dirSetFilePermissions = dirSetFilePermissions,
            .dirSetTimestamps = dirSetTimestamps,
            .dirHardLink = dirHardLink,

            .fileStat = fileStat,
            .fileLength = fileLength,
            .fileClose = fileClose,
            .fileWritePositional = fileWritePositional,
            .fileWriteFileStreaming = fileWriteFileStreaming,
            .fileWriteFilePositional = fileWriteFilePositional,
            .fileReadPositional = fileReadPositional,
            .fileSeekBy = fileSeekBy,
            .fileSeekTo = fileSeekTo,
            .fileSync = fileSync,
            .fileIsTty = fileIsTty,
            .fileEnableAnsiEscapeCodes = fileEnableAnsiEscapeCodes,
            .fileSupportsAnsiEscapeCodes = fileSupportsAnsiEscapeCodes,
            .fileSetLength = fileSetLength,
            .fileSetOwner = fileSetOwner,
            .fileSetPermissions = fileSetPermissions,
            .fileSetTimestamps = fileSetTimestamps,
            .fileLock = fileLock,
            .fileTryLock = fileTryLock,
            .fileUnlock = fileUnlock,
            .fileDowngradeLock = fileDowngradeLock,
            .fileRealPath = fileRealPath,
            .fileHardLink = fileHardLink,

            .fileMemoryMapCreate = fileMemoryMapCreate,
            .fileMemoryMapDestroy = fileMemoryMapDestroy,
            .fileMemoryMapSetLength = fileMemoryMapSetLength,
            .fileMemoryMapRead = fileMemoryMapRead,
            .fileMemoryMapWrite = fileMemoryMapWrite,

            .processExecutableOpen = processExecutableOpen,
            .processExecutablePath = processExecutablePath,
            .lockStderr = lockStderr,
            .tryLockStderr = tryLockStderr,
            .unlockStderr = unlockStderr,
            .processCurrentPath = processCurrentPath,
            .processSetCurrentDir = processSetCurrentDir,
            .processSetCurrentPath = processSetCurrentPath,
            .processReplace = processReplace,
            .processSpawn = processSpawn,
            .childWait = childWait,
            .childKill = childKill,

            .progressParentFile = progressParentFile,
            .inheritParentDir = inheritParentDir,
            .inheritParentFile = inheritParentFile,

            .now = now,
            .clockResolution = clockResolution,
            .sleep = sleep,

            .random = random,
            .randomSecure = randomSecure,

            .netListenIp = switch (native_os) {
                .windows => windows_impl.netListenIpWindows,
                else => net_impl.netListenIpPosix,
            },
            .netListenUnix = switch (native_os) {
                .windows => windows_impl.netListenUnixWindows,
                else => net_impl.netListenUnixPosix,
            },
            .netAccept = switch (native_os) {
                .windows => windows_impl.netAcceptWindows,
                else => net_impl.netAcceptPosix,
            },
            .netBindIp = switch (native_os) {
                .windows => windows_impl.netBindIpWindows,
                else => net_impl.netBindIpPosix,
            },
            .netConnectIp = switch (native_os) {
                .windows => windows_impl.netConnectIpWindows,
                else => net_impl.netConnectIpPosix,
            },
            .netConnectUnix = switch (native_os) {
                .windows => windows_impl.netConnectUnixWindows,
                else => net_impl.netConnectUnixPosix,
            },
            .netSocketCreatePair = net_impl.netSocketCreatePair,
            .netClose = net_impl.netClose,
            .netShutdown = switch (native_os) {
                .windows => windows_impl.netShutdownWindows,
                else => net_impl.netShutdownPosix,
            },
            .netWriteFile = net_impl.netWriteFile,
            .netInterfaceNameResolve = net_impl.netInterfaceNameResolve,
            .netInterfaceName = net_impl.netInterfaceName,
            .netLookup = net_impl.netLookup,
        },
    };
}

pub const socket_flags_unsupported = is_darwin or native_os == .haiku;
pub const have_accept4 = !socket_flags_unsupported;
const have_flock_open_flags = @hasField(posix.O, "EXLOCK");
pub const have_networking = std.options.networking and native_os != .wasi;
const have_flock = @TypeOf(posix.system.flock) != void;
pub const have_sendmmsg = native_os == .linux;
const have_futex = switch (builtin.cpu.arch) {
    .wasm32, .wasm64 => builtin.cpu.has(.wasm, .atomics),
    else => true,
};
const have_preadv = switch (native_os) {
    .windows, .haiku => false,
    else => true,
};
const have_sig_io = posix.SIG != void and @hasField(posix.SIG, "IO");
const have_sig_pipe = posix.SIG != void and @hasField(posix.SIG, "PIPE");
const have_sendfile = if (builtin.link_libc) @TypeOf(std.c.sendfile) != void else native_os == .linux;
const have_copy_file_range = switch (native_os) {
    .linux, .freebsd => true,
    else => false,
};
const have_fcntl = switch (native_os) {
    .linux, .dragonfly, .freebsd, .netbsd, .openbsd, .illumos, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => true,
    else => false,
};
const have_fcopyfile = is_darwin;
const have_fchmodat2 = native_os == .linux and
    (builtin.os.isAtLeast(.linux, .{ .major = 6, .minor = 6, .patch = 0 }) orelse true) and
    (builtin.abi.isAndroid() or !std.c.versionCheck(.{ .major = 2, .minor = 32, .patch = 0 }));
const have_fchmodat_flags = native_os != .linux or
    (!builtin.abi.isAndroid() and std.c.versionCheck(.{ .major = 2, .minor = 32, .patch = 0 }));

const have_fchown = switch (native_os) {
    .wasi, .windows => false,
    else => true,
};

const have_fchmod = switch (native_os) {
    .windows => false,
    .wasi => builtin.link_libc,
    else => true,
};

const have_waitid = switch (native_os) {
    .linux => @hasField(std.os.linux.SYS, "waitid"),
    else => false,
};

/// YasOS (yasos.zig): Linux in Zig's eyes, reached through its libc, on an
/// M-profile core without an MMU.  No fork: a child is a vfork + exec done in
/// C (`yz_spawn`, the YasOS runtime of the device compiler), and waiting is
/// `waitpid` (its wait4 has no resource usage to give).
const is_yasos = std.is_yasos;

const have_wait4 = switch (native_os) {
    .linux => @hasField(std.os.linux.SYS, "wait4"),
    .dragonfly, .freebsd, .netbsd, .openbsd, .illumos, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => true,
    else => false,
};

const have_mmap = switch (native_os) {
    .wasi, .windows => false,
    else => true,
};
const have_poll = switch (native_os) {
    .wasi, .windows => false,
    else => true,
};

const open_sym = if (posix.lfs64_abi) posix.system.open64 else posix.system.open;
const openat_sym = if (posix.lfs64_abi) posix.system.openat64 else posix.system.openat;
const fstat_sym = if (posix.lfs64_abi) posix.system.fstat64 else posix.system.fstat;
const fstatat_sym = if (posix.lfs64_abi) posix.system.fstatat64 else posix.system.fstatat;
const lseek_sym = if (posix.lfs64_abi) posix.system.lseek64 else posix.system.lseek;
const preadv_sym = if (posix.lfs64_abi) posix.system.preadv64 else posix.system.preadv;
const pread_sym = if (posix.lfs64_abi) posix.system.pread64 else posix.system.pread;
const ftruncate_sym = if (posix.lfs64_abi) posix.system.ftruncate64 else posix.system.ftruncate;
const pwritev_sym = if (posix.lfs64_abi) posix.system.pwritev64 else posix.system.pwritev;
const pwrite_sym = if (posix.lfs64_abi) posix.system.pwrite64 else posix.system.pwrite;
const sendfile_sym = if (posix.lfs64_abi) posix.system.sendfile64 else posix.system.sendfile;
const mmap_sym = if (posix.lfs64_abi) posix.system.mmap64 else posix.system.mmap;

const linux_copy_file_range_use_c = std.c.versionCheck(if (builtin.abi.isAndroid()) .{
    .major = 34,
    .minor = 0,
    .patch = 0,
} else .{
    .major = 2,
    .minor = 27,
    .patch = 0,
});
const linux_copy_file_range_sys = if (linux_copy_file_range_use_c) std.c else std.os.linux;

const statx_use_c = std.c.versionCheck(if (builtin.abi.isAndroid())
    .{ .major = 30, .minor = 0, .patch = 0 }
else
    .{ .major = 2, .minor = 28, .patch = 0 });

const use_libc_getrandom = std.c.versionCheck(if (builtin.abi.isAndroid()) .{
    .major = 28,
    .minor = 0,
    .patch = 0,
} else .{
    .major = 2,
    .minor = 25,
    .patch = 0,
});

const use_dev_urandom = @TypeOf(posix.system.getrandom) == void and native_os == .linux;

fn crashHandler(userdata: ?*anyopaque) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const thread = Thread.current orelse return;
    thread.status.store(.{ .cancelation = .canceled, .awaitable = .null }, .monotonic);
    thread.cancel_protection = .blocked;
}

fn async(
    userdata: ?*anyopaque,
    result: []u8,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) ?*Io.AnyFuture {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (builtin.single_threaded) {
        start(context.ptr, result.ptr);
        return null;
    }

    const gpa = t.allocator;
    const future = Future.create(gpa, result.len, result_alignment, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => {
            start(context.ptr, result.ptr);
            return null;
        },
    };

    mutexLockUncancelable(&t.mutex);

    const busy_count = t.busy_count;

    if (busy_count >= @backingInt(t.async_limit)) {
        mutexUnlock(&t.mutex);
        future.destroy(gpa);
        start(context.ptr, result.ptr);
        return null;
    }

    t.busy_count = busy_count + 1;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch {
            t.wait_group.finish();
            t.busy_count = busy_count;
            mutexUnlock(&t.mutex);
            future.destroy(gpa);
            start(context.ptr, result.ptr);
            return null;
        };
        thread.detach();
    }

    t.run_queue.prepend(&future.runnable.node);

    mutexUnlock(&t.mutex);
    condSignal(&t.cond);
    return @ptrCast(future);
}

fn concurrent(
    userdata: ?*anyopaque,
    result_len: usize,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) Io.ConcurrentError!*Io.AnyFuture {
    if (builtin.single_threaded) return error.ConcurrencyUnavailable;

    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const gpa = t.allocator;
    const future = Future.create(gpa, result_len, result_alignment, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => return error.ConcurrencyUnavailable,
    };
    errdefer future.destroy(gpa);

    mutexLockUncancelable(&t.mutex);
    defer mutexUnlock(&t.mutex);

    const busy_count = t.busy_count;

    if (busy_count >= @backingInt(t.concurrent_limit))
        return error.ConcurrencyUnavailable;

    t.busy_count = busy_count + 1;
    errdefer t.busy_count = busy_count;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        errdefer t.wait_group.finish();

        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch
            return error.ConcurrencyUnavailable;

        thread.detach();
    }

    t.run_queue.prepend(&future.runnable.node);

    condSignal(&t.cond);
    return @ptrCast(future);
}

fn groupAsync(
    userdata: ?*anyopaque,
    type_erased: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    if (builtin.single_threaded) return groupAsyncEager(start, context.ptr);

    const gpa = t.allocator;
    const task = Group.Task.create(gpa, g, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => return groupAsyncEager(start, context.ptr),
    };

    mutexLockUncancelable(&t.mutex);

    const busy_count = t.busy_count;

    if (busy_count >= @backingInt(t.async_limit)) {
        mutexUnlock(&t.mutex);
        task.destroy(gpa);
        return groupAsyncEager(start, context.ptr);
    }

    t.busy_count = busy_count + 1;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch {
            t.wait_group.finish();
            t.busy_count = busy_count;
            mutexUnlock(&t.mutex);
            task.destroy(gpa);
            return groupAsyncEager(start, context.ptr);
        };
        thread.detach();
    }

    // TODO: if this logic is changed to be lock-free, this `fetchAdd` must be released by the queue
    // prepend so that the task doesn't finish without observing this and try to decrement the count
    // below zero.
    _ = g.status().fetchAdd(.{
        .num_running = 1,
        .have_awaiter = false,
        .canceled = false,
    }, .monotonic);
    t.run_queue.prepend(&task.runnable.node);

    mutexUnlock(&t.mutex);
    condSignal(&t.cond);
}
fn groupAsyncEager(
    start: *const fn (context: *const anyopaque) void,
    context: *const anyopaque,
) void {
    start(context);
}

fn groupConcurrent(
    userdata: ?*anyopaque,
    type_erased: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) Io.ConcurrentError!void {
    if (builtin.single_threaded) return error.ConcurrencyUnavailable;

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    const gpa = t.allocator;
    const task = Group.Task.create(gpa, g, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => return error.ConcurrencyUnavailable,
    };
    errdefer task.destroy(gpa);

    mutexLockUncancelable(&t.mutex);
    defer mutexUnlock(&t.mutex);

    const busy_count = t.busy_count;

    if (busy_count >= @backingInt(t.concurrent_limit))
        return error.ConcurrencyUnavailable;

    t.busy_count = busy_count + 1;
    errdefer t.busy_count = busy_count;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        errdefer t.wait_group.finish();

        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch
            return error.ConcurrencyUnavailable;

        thread.detach();
    }

    // TODO: if this logic is changed to be lock-free, this `fetchAdd` must be released by the queue
    // prepend so that the task doesn't finish without observing this and try to decrement the count
    // below zero.
    _ = g.status().fetchAdd(.{
        .num_running = 1,
        .have_awaiter = false,
        .canceled = false,
    }, .monotonic);
    t.run_queue.prepend(&task.runnable.node);

    condSignal(&t.cond);
}

fn groupAwait(userdata: ?*anyopaque, type_erased: *Io.Group, initial_token: *anyopaque) Io.Cancelable!void {
    _ = initial_token; // we need to load `token` *after* the group finishes
    if (builtin.single_threaded) unreachable; // nothing to await
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    var num_completed: std.atomic.Value(u32) = .init(0);
    g.awaiter().* = &num_completed;

    const pre_await_status = g.status().fetchOr(.{
        .num_running = 0,
        .have_awaiter = true,
        .canceled = false,
    }, .acq_rel); // acquire results if complete; release `g.awaiter()`

    assert(!pre_await_status.have_awaiter);
    assert(!pre_await_status.canceled);
    if (pre_await_status.num_running == 0) {
        // Already done. Since the group is finished, it's illegal to spawn more tasks in it
        // until we return, so we can access `g.status()` non-atomically.
        g.status().raw.have_awaiter = false;
        return;
    }

    while (Thread.futexWait(&num_completed.raw, 0, null)) {
        switch (num_completed.load(.acquire)) { // acquire task results
            0 => continue,
            1 => break,
            else => unreachable, // group was reused before `await` returned
        }
    } else |err| switch (err) {
        error.Canceled => {
            const pre_cancel_status = g.status().fetchOr(.{
                .num_running = 0,
                .have_awaiter = false,
                .canceled = true,
            }, .acq_rel); // acquire results if complete; release `g.awaiter()`
            assert(pre_cancel_status.have_awaiter);
            assert(!pre_cancel_status.canceled);

            // Even if `pre_cancel_status.num_running == 0`, we still need to wait for the signal,
            // because in that case the last member of the group is already trying to modify it.
            // However, if we know everything is done, we *can* skip signaling blocked threads.
            const skip_signals = pre_cancel_status.num_running == 0;
            g.waitForCancelWithSignaling(t, &num_completed, skip_signals);

            // The group is finished, so it's illegal to spawn more tasks in it until we return, so
            // we can access `g.status()` non-atomically.
            g.status().raw.canceled = false;
            g.status().raw.have_awaiter = false;
            return error.Canceled;
        },
    }

    // The group is finished, so it's illegal to spawn more tasks in it until we return, so
    // we can access `g.status()` non-atomically.
    g.status().raw.have_awaiter = false;
}

fn groupCancel(userdata: ?*anyopaque, type_erased: *Io.Group, initial_token: *anyopaque) void {
    _ = initial_token;
    if (builtin.single_threaded) unreachable; // nothing to cancel
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    var num_completed: std.atomic.Value(u32) = .init(0);
    g.awaiter().* = &num_completed;

    const pre_cancel_status = g.status().fetchOr(.{
        .num_running = 0,
        .have_awaiter = true,
        .canceled = true,
    }, .acq_rel); // acquire results if complete; release `g.awaiter()`

    assert(!pre_cancel_status.have_awaiter);
    assert(!pre_cancel_status.canceled);
    if (pre_cancel_status.num_running == 0) {
        // Already done. Since the group is finished, it's illegal to spawn more tasks in it
        // until we return, so we can access `g.status()` non-atomically.
        g.status().raw.have_awaiter = false;
        g.status().raw.canceled = false;
        return;
    }

    g.waitForCancelWithSignaling(t, &num_completed, false);

    g.status().raw = .{ .num_running = 0, .have_awaiter = false, .canceled = false };
}

fn recancel(userdata: ?*anyopaque) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    recancelInner();
}
fn recancelInner() void {
    const thread = Thread.current.?; // called `recancel` but was not canceled
    switch (thread.status.fetchXor(.{
        .cancelation = @fromBackingInt(@intCast(0b001)),
        .awaitable = .null,
    }, .monotonic).cancelation) {
        .canceled => {},
        .none => unreachable, // called `recancel` but was not canceled
        .canceling => unreachable, // called `recancel` but cancelation was already pending
        .parked => unreachable,
        .blocked => unreachable,
        .blocked_alertable => unreachable,
        .blocked_alertable_canceling => unreachable,
        .blocked_canceling => unreachable,
    }
}

pub fn swapCancelProtection(userdata: ?*anyopaque, new: Io.CancelProtection) Io.CancelProtection {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const thread = Thread.current orelse return .unblocked;
    const old = thread.cancel_protection;
    thread.cancel_protection = new;
    return old;
}

fn checkCancel(userdata: ?*anyopaque) Io.Cancelable!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return Thread.checkCancel();
}

fn await(
    userdata: ?*anyopaque,
    any_future: *Io.AnyFuture,
    result: []u8,
    result_alignment: Alignment,
) void {
    _ = result_alignment;
    if (builtin.single_threaded) unreachable; // nothing to await
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const future: *Future = @ptrCast(@alignCast(any_future));

    var num_completed: std.atomic.Value(u32) = .init(0);
    future.awaiter = &num_completed;

    const pre_await_status = future.status.fetchOr(.{
        .tag = .pending_awaited,
        .thread = .null,
    }, .acq_rel); // acquire results if complete; release `future.awaiter`
    switch (pre_await_status.tag) {
        .pending => while (Thread.futexWait(&num_completed.raw, 0, null)) {
            switch (num_completed.load(.acquire)) { // acquire task results
                0 => continue,
                1 => break,
                else => unreachable, // group was reused before `await` returned
            }
        } else |err| switch (err) {
            error.Canceled => {
                const pre_cancel_status = future.status.fetchOr(.{
                    .tag = .pending_canceled,
                    .thread = .null,
                }, .acq_rel); // acquire results if complete; release `future.awaiter`
                const done_status = switch (pre_cancel_status.tag) {
                    .pending => unreachable, // invalid state: we already awaited
                    .pending_awaited => done_status: {
                        const working_thread = pre_cancel_status.thread.unpack();
                        future.waitForCancelWithSignaling(t, &num_completed, @alignCast(working_thread));
                        break :done_status future.status.load(.monotonic);
                    },
                    .pending_canceled => unreachable, // `await` raced with `cancel`
                    .done => done_status: {
                        // The task just finished, but we still need to wait for the signal, because the
                        // task thread already figured out that they need to update `future.awaiter`.
                        future.waitForCancelWithSignaling(t, &num_completed, null);
                        // Also, we have clobbered `future.status.tag` to `.pending_canceled`, but that's
                        // not actually a problem for the logic below.
                        break :done_status pre_cancel_status;
                    },
                };
                // If the future did not acknowledge the cancelation, we need to mark it outstanding
                // for us. Because `done_status.tag == .done`, the information about whether there
                // was an acknowledged cancelation is encoded in `done_status.thread`.
                assert(done_status.tag == .done);
                switch (done_status.thread) {
                    .null => recancelInner(), // cancelation was not acknowledged, so it's ours
                    .all_ones => {}, // cancelation was acknowledged, so it was this task's job to propagate it
                    _ => unreachable,
                }
            },
        },
        .pending_awaited => unreachable, // `await` raced with `await`
        .pending_canceled => unreachable, // `await` raced with `cancel`
        .done => {},
    }
    @memcpy(result, future.resultPointer());
    future.destroy(t.allocator);
}

fn cancel(
    userdata: ?*anyopaque,
    any_future: *Io.AnyFuture,
    result: []u8,
    result_alignment: Alignment,
) void {
    _ = result_alignment;
    if (builtin.single_threaded) unreachable; // nothing to cancel
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const future: *Future = @ptrCast(@alignCast(any_future));

    var num_completed: std.atomic.Value(u32) = .init(0);
    future.awaiter = &num_completed;

    const pre_cancel_status = future.status.fetchOr(.{
        .tag = .pending_canceled,
        .thread = .null,
    }, .acq_rel); // acquire results if complete; release `future.awaiter`
    switch (pre_cancel_status.tag) {
        .pending => {
            const working_thread = pre_cancel_status.thread.unpack();
            future.waitForCancelWithSignaling(t, &num_completed, @alignCast(working_thread));
        },
        .pending_awaited => unreachable, // `await` raced with `await`
        .pending_canceled => unreachable, // `await` raced with `cancel`
        .done => {},
    }
    @memcpy(result, future.resultPointer());
    future.destroy(t.allocator);
}

fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: Io.Timeout) Io.Cancelable!void {
    if (builtin.single_threaded) {
        assert(timeout != .none); // Deadlock.
        return;
    }
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const t_io = io(t);
    const timeout_ns: ?u64 = ns: {
        const d = timeout.toDurationFromNow(t_io) orelse break :ns null;
        break :ns std.math.lossyCast(u64, d.raw.toNanoseconds());
    };
    return Thread.futexWait(ptr, expected, timeout_ns);
}

fn futexWaitUncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
    if (builtin.single_threaded) unreachable; // Deadlock.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    Thread.futexWaitUncancelable(ptr, expected, null);
}

fn futexWake(userdata: ?*anyopaque, ptr: *const u32, max_waiters: u32) void {
    if (builtin.single_threaded) return; // Nothing to wake up.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    Thread.futexWake(ptr, max_waiters);
}

fn operate(userdata: ?*anyopaque, operation: Io.Operation) Io.Cancelable!Io.Operation.Result {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    switch (operation) {
        .file_read_streaming => |o| return .{
            .file_read_streaming = fileReadStreaming(t, o.file, o.data) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => |e| e,
            },
        },
        .file_write_streaming => |o| return .{
            .file_write_streaming = fileWriteStreaming(t, o.file, o.header, o.data, o.splat) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => |e| e,
            },
        },
        .device_io_control => |*o| return .{ .device_io_control = try deviceIoControl(o) },
        .net_receive => |*o| return .{ .net_receive = o: {
            if (!have_networking) break :o .{ error.NetworkDown, 0 };
            if (is_windows) break :o windows_impl.netReceiveWindows(t, o.socket_handle, o.message_buffer, o.data_buffer, o.flags);
            net_impl.netReceivePosix(o.socket_handle, &o.message_buffer[0], o.data_buffer, o.flags, false) catch |err| switch (err) {
                error.Canceled => |e| return e,
                error.WouldBlock => unreachable,
                else => |e| break :o .{ e, 0 },
            };
            break :o .{ null, 1 };
        } },
        .net_send => |*o| return .{
            .net_send = o: {
                if (!have_networking) break :o .{ error.NetworkDown, 0 };
                if (is_windows) break :o windows_impl.netSendWindows(t, o.socket_handle, o.messages, o.flags);
                const send_err, const sent = net_impl.netSendPosix(t, o.socket_handle, o.messages, o.flags, false);
                if (send_err) |err| switch (err) {
                    error.Canceled => |e| if (sent == 0) {
                        return e;
                    } else {
                        // Leave the `error.Canceled` for later, but don't try to send any more messages.
                        recancelInner();
                        break :o .{ null, sent };
                    },
                    error.WouldBlock => unreachable,
                    else => |e| break :o .{ e, sent },
                };
                break :o .{ null, sent };
            },
        },
        .net_read => |o| return .{
            .net_read = net_impl.netRead(o.socket_handle, o.data, o.control) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => |e| e,
            },
        },
        .net_write => |o| return .{
            .net_write = (if (is_windows)
                windows_impl.netWriteWindows(o.socket_handle, o.header, o.data, o.splat, o.control)
            else
                net_impl.netWritePosix(o.socket_handle, o.header, o.data, o.splat, o.control)) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => |e| e,
            },
        },
    }
}

fn batchAwaitAsync(userdata: ?*anyopaque, b: *Io.Batch) Io.Cancelable!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (is_windows) {
        windows_impl.batchDrainSubmittedWindows(t, b, false) catch |err| switch (err) {
            error.ConcurrencyUnavailable => unreachable, // passed concurrency=false
            else => |e| return e,
        };
        const alertable_syscall = try AlertableSyscall.start();
        while (b.pending.head != .none and b.completed.head == .none) waitForApcOrAlert();
        alertable_syscall.finish();
        return;
    }
    if (have_poll) {
        var poll_buffer: [poll_buffer_len]posix.pollfd = undefined;
        var poll_len: u32 = 0;
        {
            var index = b.submitted.head;
            while (index != .none and poll_len < poll_buffer_len) {
                const submission = &b.storage[index.toIndex()].submission;
                switch (submission.operation) {
                    .file_read_streaming => |o| {
                        poll_buffer[poll_len] = .{
                            .fd = o.file.handle,
                            .events = posix.POLL.IN | posix.POLL.ERR,
                        };
                        poll_len += 1;
                    },
                    .file_write_streaming => |o| {
                        poll_buffer[poll_len] = .{
                            .fd = o.file.handle,
                            .events = posix.POLL.OUT | posix.POLL.ERR,
                        };
                        poll_len += 1;
                    },
                    .device_io_control => |o| {
                        poll_buffer[poll_len] = .{
                            .fd = o.file.handle,
                            .events = posix.POLL.OUT | posix.POLL.IN | posix.POLL.ERR,
                        };
                        poll_len += 1;
                    },
                    .net_receive => |*o| {
                        poll_buffer[poll_len] = .{
                            .fd = o.socket_handle,
                            .events = posix.POLL.IN | posix.POLL.ERR,
                        };
                        poll_len += 1;
                    },
                    .net_send => |*o| {
                        poll_buffer[poll_len] = .{
                            .fd = o.socket_handle,
                            .events = posix.POLL.OUT | posix.POLL.ERR,
                        };
                        poll_len += 1;
                    },
                    .net_read => |o| {
                        poll_buffer[poll_len] = .{
                            .fd = o.socket_handle,
                            .events = posix.POLL.IN | posix.POLL.ERR,
                        };
                        poll_len += 1;
                    },
                    .net_write => |o| {
                        poll_buffer[poll_len] = .{
                            .fd = o.socket_handle,
                            .events = posix.POLL.OUT | posix.POLL.ERR,
                        };
                        poll_len += 1;
                    },
                }
                index = submission.node.next;
            }
        }
        switch (poll_len) {
            0 => return,
            1 => {},
            else => while (true) {
                const timeout_ms: i32 = t: {
                    if (b.completed.head != .none) {
                        // It is legal to call batchWait with already completed
                        // operations in the ring. In such case, we need to avoid
                        // blocking in the poll syscall, but we can still take this
                        // opportunity to find additional ready operations.
                        break :t 0;
                    }
                    break :t std.math.maxInt(i32);
                };
                const syscall = try Syscall.start();
                const rc = posix.system.poll(&poll_buffer, poll_len, timeout_ms);
                syscall.finish();
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        if (rc == 0) {
                            if (b.completed.head != .none) {
                                // Since there are already completions available in the
                                // queue, this is neither a timeout nor a case for
                                // retrying.
                                return;
                            }
                            continue;
                        }
                        var prev_index: Io.Operation.OptionalIndex = .none;
                        var index = b.submitted.head;
                        for (poll_buffer[0..poll_len]) |poll_entry| {
                            const storage = &b.storage[index.toIndex()];
                            const submission = &storage.submission;
                            const next_index = submission.node.next;
                            if (poll_entry.revents != 0) {
                                const result = try operate(t, submission.operation);

                                switch (prev_index) {
                                    .none => b.submitted.head = next_index,
                                    else => b.storage[prev_index.toIndex()].submission.node.next = next_index,
                                }
                                if (next_index == .none) b.submitted.tail = prev_index;

                                switch (b.completed.tail) {
                                    .none => b.completed.head = index,
                                    else => |tail_index| b.storage[tail_index.toIndex()].completion.node.next = index,
                                }
                                storage.* = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
                                b.completed.tail = index;
                            } else prev_index = index;
                            index = next_index;
                        }
                        assert(index == .none);
                        return;
                    },
                    .INTR => continue,
                    else => break,
                }
            },
        }
    }

    var tail_index = b.completed.tail;
    defer b.completed.tail = tail_index;
    var index = b.submitted.head;
    errdefer b.submitted.head = index;
    while (index != .none) {
        const storage = &b.storage[index.toIndex()];
        const submission = &storage.submission;
        const next_index = submission.node.next;
        const result = try operate(t, submission.operation);

        switch (tail_index) {
            .none => b.completed.head = index,
            else => b.storage[tail_index.toIndex()].completion.node.next = index,
        }
        storage.* = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
        tail_index = index;
        index = next_index;
    }
    b.submitted = .{ .head = .none, .tail = .none };
}

fn batchAwaitConcurrent(userdata: ?*anyopaque, b: *Io.Batch, timeout: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (is_windows) {
        const deadline: ?Io.Clock.Timestamp = timeout.toTimestamp(io(t));
        try windows_impl.batchDrainSubmittedWindows(t, b, true);
        while (b.pending.head != .none and b.completed.head == .none) {
            var delay_interval: windows.LARGE_INTEGER = interval: {
                const d = deadline orelse break :interval std.math.minInt(windows.LARGE_INTEGER);
                break :interval windows_impl.timeoutToWindowsInterval(.{ .deadline = d }).?;
            };
            const alertable_syscall = try AlertableSyscall.start();
            const delay_rc = windows.ntdll.NtDelayExecution(.TRUE, &delay_interval);
            alertable_syscall.finish();
            switch (delay_rc) {
                .SUCCESS, .TIMEOUT => {
                    // The thread woke due to the timeout. Although spurious
                    // timeouts are OK, when no deadline is passed we must not
                    // return `error.Timeout`.
                    if (timeout != .none and b.completed.head == .none) return error.Timeout;
                },
                else => {},
            }
        }
        return;
    }
    if (native_os == .wasi) {
        // TODO call poll_oneoff
        return error.ConcurrencyUnavailable;
    }
    if (!have_poll) return error.ConcurrencyUnavailable;
    var poll_buffer: [poll_buffer_len]posix.pollfd = undefined;
    var poll_storage: struct {
        gpa: Allocator,
        batch: *Io.Batch,
        slice: []posix.pollfd,
        len: u32,

        fn add(storage: *@This(), fd: File.Handle, events: @FieldType(posix.pollfd, "events")) Io.ConcurrentError!void {
            const len = storage.len;
            if (len == poll_buffer_len) {
                const slice: []posix.pollfd = if (storage.batch.userdata) |batch_userdata|
                    @as([*]posix.pollfd, @ptrCast(@alignCast(batch_userdata)))[0..storage.batch.storage.len]
                else allocation: {
                    const allocation = storage.gpa.alloc(posix.pollfd, storage.batch.storage.len) catch
                        return error.ConcurrencyUnavailable;
                    storage.batch.userdata = allocation.ptr;
                    break :allocation allocation;
                };
                @memcpy(slice[0..poll_buffer_len], storage.slice);
                storage.slice = slice;
            }
            storage.slice[len] = .{
                .fd = fd,
                .events = events,
            };
            storage.len = len + 1;
        }
    } = .{ .gpa = t.allocator, .batch = b, .slice = &poll_buffer, .len = 0 };
    {
        var index = b.submitted.head;
        while (index != .none) {
            const storage = &b.storage[index.toIndex()];
            const submission = storage.submission;
            switch (submission.operation) {
                .file_read_streaming => |o| try poll_storage.add(o.file.handle, posix.POLL.IN | posix.POLL.ERR),
                .file_write_streaming => |o| try poll_storage.add(o.file.handle, posix.POLL.OUT | posix.POLL.ERR),
                .device_io_control => |o| try poll_storage.add(o.file.handle, posix.POLL.IN | posix.POLL.OUT | posix.POLL.ERR),
                .net_receive => |*o| nb: {
                    var data_i: usize = 0;
                    const result: Io.Operation.Result = .{ .net_receive = for (o.message_buffer, 0..) |*msg, msg_i| {
                        const remaining_data_buffer = o.data_buffer[data_i..];
                        net_impl.netReceivePosix(o.socket_handle, msg, remaining_data_buffer, o.flags, true) catch |err| switch (err) {
                            error.Canceled => |e| return e,
                            error.WouldBlock => {
                                if (msg_i != 0) break .{ null, msg_i };
                                try poll_storage.add(o.socket_handle, posix.POLL.IN | posix.POLL.ERR);
                                break :nb;
                            },
                            else => |e| break .{ e, msg_i },
                        };
                        data_i += msg.data.len;
                    } else .{ null, o.message_buffer.len } };
                    switch (b.completed.tail) {
                        .none => b.completed.head = index,
                        else => |tail_index| b.storage[tail_index.toIndex()].completion.node.next = index,
                    }
                    storage.* = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
                    b.completed.tail = index;
                },
                .net_send => |*o| nb: {
                    const result: Io.Operation.Result = .{
                        .net_send = o: {
                            const send_err, const sent = net_impl.netSendPosix(t, o.socket_handle, o.messages, o.flags, true);
                            if (send_err) |err| switch (err) {
                                error.Canceled => |e| if (sent == 0) {
                                    return e;
                                } else {
                                    // Leave the `error.Canceled` for later, but don't try to send any more messages.
                                    recancelInner();
                                    break :o .{ null, sent };
                                },
                                error.WouldBlock => {
                                    if (sent != 0) break :o .{ null, sent };
                                    try poll_storage.add(o.socket_handle, posix.POLL.OUT | posix.POLL.ERR);
                                    break :nb;
                                },
                                else => |e| break :o .{ e, sent },
                            };
                            break :o .{ null, sent };
                        },
                    };
                    switch (b.completed.tail) {
                        .none => b.completed.head = index,
                        else => |tail_index| b.storage[tail_index.toIndex()].completion.node.next = index,
                    }
                    storage.* = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
                    b.completed.tail = index;
                },
                .net_read => |o| try poll_storage.add(o.socket_handle, posix.POLL.IN | posix.POLL.ERR),
                .net_write => |o| try poll_storage.add(o.socket_handle, posix.POLL.OUT | posix.POLL.ERR),
            }
            index = submission.node.next;
        }
    }
    switch (poll_storage.len) {
        0 => return,
        1 => if (timeout == .none and b.completed.head == .none) {
            const index = b.submitted.head;
            const storage = &b.storage[index.toIndex()];
            const result = try operate(t, storage.submission.operation);

            b.submitted = .{ .head = .none, .tail = .none };

            switch (b.completed.tail) {
                .none => b.completed.head = index,
                else => |tail_index| b.storage[tail_index.toIndex()].completion.node.next = index,
            }
            storage.* = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
            b.completed.tail = index;
            return;
        },
        else => {},
    }
    const t_io = io(t);
    const deadline = timeout.toTimestamp(t_io);
    while (true) {
        const timeout_ms: i32 = t: {
            if (b.completed.head != .none) {
                // It is legal to call batchWait with already completed
                // operations in the ring. In such case, we need to avoid
                // blocking in the poll syscall, but we can still take this
                // opportunity to find additional ready operations.
                break :t 0;
            }
            const d = deadline orelse break :t -1;
            const duration = d.durationFromNow(t_io);
            break :t @min(@max(0, duration.raw.toMilliseconds()), std.math.maxInt(i32));
        };
        const syscall = try Syscall.start();
        const rc = posix.system.poll(poll_storage.slice.ptr, poll_storage.len, timeout_ms);
        syscall.finish();
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) {
                    if (b.completed.head != .none) {
                        // Since there are already completions available in the
                        // queue, this is neither a timeout nor a case for
                        // retrying.
                        return;
                    }
                    // Although spurious timeouts are OK, when no deadline is
                    // passed we must not return `error.Timeout`.
                    if (deadline == null) continue;
                    return error.Timeout;
                }
                var prev_index: Io.Operation.OptionalIndex = .none;
                var index = b.submitted.head;
                for (poll_storage.slice[0..poll_storage.len]) |poll_entry| {
                    const submission = &b.storage[index.toIndex()].submission;
                    const next_index = submission.node.next;
                    if (poll_entry.revents != 0) {
                        const result = try operate(t, submission.operation);

                        switch (prev_index) {
                            .none => b.submitted.head = next_index,
                            else => b.storage[prev_index.toIndex()].submission.node.next = next_index,
                        }
                        if (next_index == .none) b.submitted.tail = prev_index;

                        switch (b.completed.tail) {
                            .none => b.completed.head = index,
                            else => |tail_index| b.storage[tail_index.toIndex()].completion.node.next = index,
                        }
                        b.completed.tail = index;
                        b.storage[index.toIndex()] = .{ .completion = .{
                            .node = .{ .next = .none },
                            .result = result,
                        } };
                    } else prev_index = index;
                    index = next_index;
                }
                assert(index == .none);
                return;
            },
            .INTR => continue,
            else => return error.ConcurrencyUnavailable,
        }
    }
}

fn batchCancel(userdata: ?*anyopaque, b: *Io.Batch) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (is_windows) {
        if (b.pending.head == .none) return;
        waitForApcOrAlert();
        var index = b.pending.head;
        while (index != .none) {
            const pending = &b.storage[index.toIndex()].pending;
            const operation_userdata: *windows_impl.WindowsBatchOperationUserdata = .fromErased(&pending.userdata);
            var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
            _ = windows.ntdll.NtCancelIoFileEx(operation_userdata.file, &operation_userdata.iosb, &cancel_iosb);
            index = pending.node.next;
        }
        while (b.pending.head != .none) waitForApcOrAlert();
    } else if (b.userdata) |batch_userdata| {
        const poll_storage: [*]posix.pollfd = @ptrCast(@alignCast(batch_userdata));
        t.allocator.free(poll_storage[0..b.storage.len]);
        b.userdata = null;
    }
}

fn submitComplete(ring: []u32, complete_tail: *Io.Batch.RingIndex, op: u32) void {
    const ct = complete_tail.*;
    const len: u31 = @intCast(ring.len);
    ring[ct.index(len)] = op;
    complete_tail.* = ct.next(len);
}

const dirCreateDir = switch (native_os) {
    .windows => windows_impl.dirCreateDirWindows,
    .wasi => wasi_impl.dirCreateDirWasi,
    else => dirCreateDirPosix,
};

pub fn dirCreateDirPosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.mkdirat(dir.handle, sub_path_posix, permissions.toMode()))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ACCES => return syscall.fail(error.AccessDenied),
            .PERM => return syscall.fail(error.PermissionDenied),
            .DQUOT => return syscall.fail(error.DiskQuota),
            .EXIST => return syscall.fail(error.PathAlreadyExists),
            .LOOP => return syscall.fail(error.SymLinkLoop),
            .MLINK => return syscall.fail(error.LinkQuotaExceeded),
            .NAMETOOLONG => return syscall.fail(error.NameTooLong),
            .NOENT => return syscall.fail(error.FileNotFound),
            .NOMEM => return syscall.fail(error.SystemResources),
            .NOSPC => return syscall.fail(error.NoSpaceLeft),
            .NOTDIR => return syscall.fail(error.NotDir),
            .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
            // dragonfly: when dir_fd is unlinked from filesystem
            .NOTCONN => return syscall.fail(error.FileNotFound),
            .ILSEQ => return syscall.fail(error.BadPathName),
            .BADF => |err| return syscall.errnoBug(err), // File descriptor used after closed.
            .FAULT => |err| return syscall.errnoBug(err),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

fn dirCreateDirPath(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
) Dir.CreateDirPathError!Dir.CreatePathStatus {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    var it = Dir.path.componentIterator(sub_path);
    var status: Dir.CreatePathStatus = .existed;
    var component = it.last() orelse return error.BadPathName;
    while (true) {
        if (dirCreateDir(t, dir, component.path, permissions)) |_| {
            status = .created;
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                // It is important to return an error if it's not a directory
                // because otherwise a dangling symlink could cause an infinite
                // loop.
                const kind = try filePathKind(t, dir, component.path);
                if (kind != .directory) return error.NotDir;
            },
            error.FileNotFound => |e| {
                component = it.previous() orelse return e;
                continue;
            },
            else => |e| return e,
        }
        component = it.next() orelse return status;
    }
}

const dirCreateDirPathOpen = switch (native_os) {
    .windows => windows_impl.dirCreateDirPathOpenWindows,
    .wasi => wasi_impl.dirCreateDirPathOpenWasi,
    else => dirCreateDirPathOpenPosix,
};

fn dirCreateDirPathOpenPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.OpenOptions,
) Dir.CreateDirPathOpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const t_io = io(t);
    return dirOpenDirPosix(t, dir, sub_path, options) catch |err| switch (err) {
        error.FileNotFound => {
            _ = try dir.createDirPathStatus(t_io, sub_path, permissions);
            return dirOpenDirPosix(t, dir, sub_path, options);
        },
        else => |e| return e,
    };
}

fn dirStat(userdata: ?*anyopaque, dir: Dir) Dir.StatError!Dir.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    return fileStat(t, .{
        .handle = dir.handle,
        .flags = .{ .nonblocking = false },
    });
}

const dirStatFile = switch (native_os) {
    .linux => dirStatFileLinux,
    .windows => windows_impl.dirStatFileWindows,
    .wasi => wasi_impl.dirStatFileWasi,
    else => dirStatFilePosix,
};

fn dirStatFileLinux(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const linux = std.os.linux;
    const sys = if (statx_use_c) std.c else std.os.linux;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const flags: u32 = linux.AT.NO_AUTOMOUNT |
        @as(u32, if (!options.follow_symlinks) linux.AT.SYMLINK_NOFOLLOW else 0);

    const syscall: Syscall = try .start();
    while (true) {
        var statx = std.mem.zeroes(linux.Statx);
        switch (sys.errno(sys.statx(dir.handle, sub_path_posix, flags, linux_statx_request, &statx))) {
            .SUCCESS => {
                syscall.finish();
                return statFromLinux(&statx);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => |err| return errnoBug(err), // Handled by pathToPosix() above.
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn dirStatFilePosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const flags: u32 = if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0;

    return posixStatFile(dir.handle, sub_path_posix, flags);
}

fn posixStatFile(dir_fd: posix.fd_t, sub_path: [:0]const u8, flags: u32) Dir.StatFileError!File.Stat {
    const syscall: Syscall = try .start();
    while (true) {
        var stat = std.mem.zeroes(posix.Stat);
        switch (posix.errno(fstatat_sym(dir_fd, sub_path, &stat, flags))) {
            .SUCCESS => {
                syscall.finish();
                return statFromPosix(&stat);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .FAULT => |err| return errnoBug(err),
                    .NAMETOOLONG => return error.NameTooLong,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.FileNotFound,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn filePathKind(t: *Threaded, dir: Dir, sub_path: []const u8) !File.Kind {
    if (native_os == .linux) {
        var path_buffer: [posix.PATH_MAX]u8 = undefined;
        const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

        const linux = std.os.linux;
        const syscall: Syscall = try .start();
        while (true) {
            var statx = std.mem.zeroes(linux.Statx);
            switch (linux.errno(linux.statx(
                dir.handle,
                sub_path_posix,
                linux.AT.NO_AUTOMOUNT | linux.AT.SYMLINK_NOFOLLOW,
                .{ .TYPE = true },
                &statx,
            ))) {
                .SUCCESS => {
                    syscall.finish();
                    if (!statx.mask.TYPE) return error.Unexpected;
                    return statxKind(statx.mode);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                .NOMEM => return syscall.fail(error.SystemResources),
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    }

    const stat = try dirStatFile(t, dir, sub_path, .{ .follow_symlinks = false });
    return stat.kind;
}

fn fileLength(userdata: ?*anyopaque, file: File) File.LengthError!u64 {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    if (native_os == .linux) {
        const linux = std.os.linux;

        const syscall: Syscall = try .start();
        while (true) {
            var statx = std.mem.zeroes(linux.Statx);
            switch (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &statx))) {
                .SUCCESS => {
                    syscall.finish();
                    if (!statx.mask.SIZE) return error.Unexpected;
                    return statx.size;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ACCES => |err| return errnoBug(err),
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => |err| return errnoBug(err),
                        .LOOP => |err| return errnoBug(err),
                        .NAMETOOLONG => |err| return errnoBug(err),
                        .NOENT => |err| return errnoBug(err),
                        .NOMEM => return error.SystemResources,
                        .NOTDIR => |err| return errnoBug(err),
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    } else if (is_windows) {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.FILE.STANDARD_INFORMATION = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtQueryInformationFile(
            file.handle,
            &io_status_block,
            &info,
            @sizeOf(windows.FILE.STANDARD_INFORMATION),
            .Standard,
        )) {
            .SUCCESS => break syscall.finish(),
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |s| return syscall.unexpectedNtstatus(s),
        };
        return @as(u64, @bitCast(info.EndOfFile));
    }

    const stat = try fileStat(t, file);
    return stat.size;
}

pub const fileStat = switch (native_os) {
    .linux => fileStatLinux,
    .windows => windows_impl.fileStatWindows,
    .wasi => wasi_impl.fileStatWasi,
    else => fileStatPosix,
};

pub fn fileStatPosix(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (posix.Stat == void) return error.Streaming;

    const syscall: Syscall = try .start();
    while (true) {
        var stat = std.mem.zeroes(posix.Stat);
        switch (posix.errno(fstat_sym(file.handle, &stat))) {
            .SUCCESS => {
                syscall.finish();
                return statFromPosix(&stat);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileStatLinux(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const linux = std.os.linux;
    const sys = if (statx_use_c) std.c else std.os.linux;

    const syscall: Syscall = try .start();
    while (true) {
        var statx = std.mem.zeroes(linux.Statx);
        switch (sys.errno(sys.statx(file.handle, "", linux.AT.EMPTY_PATH, linux_statx_request, &statx))) {
            .SUCCESS => {
                syscall.finish();
                return statFromLinux(&statx);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .LOOP => |err| return errnoBug(err),
                    .NAMETOOLONG => |err| return errnoBug(err),
                    .NOENT => |err| return errnoBug(err),
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn systemBasicInformation(t: *Threaded) ?*const windows.SYSTEM.BASIC_INFORMATION {
    if (!t.system_basic_information.initialized.load(.acquire)) {
        mutexLockUncancelable(&t.mutex);
        defer mutexUnlock(&t.mutex);

        switch (windows.ntdll.NtQuerySystemInformation(
            .Basic,
            &t.system_basic_information.buffer,
            @sizeOf(windows.SYSTEM.BASIC_INFORMATION),
            null,
        )) {
            .SUCCESS => {},
            else => return null,
        }

        t.system_basic_information.initialized.store(true, .release);
    }
    return &t.system_basic_information.buffer;
}

const dirAccess = switch (native_os) {
    .windows => windows_impl.dirAccessWindows,
    .wasi => wasi_impl.dirAccessWasi,
    else => dirAccessPosix,
};

pub fn dirAccessPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.AccessOptions,
) Dir.AccessError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const flags: u32 = @as(u32, if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0);

    const mode: u32 =
        @as(u32, if (options.read) posix.R_OK else 0) |
        @as(u32, if (options.write) posix.W_OK else 0) |
        @as(u32, if (options.execute) posix.X_OK else 0);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.faccessat(dir.handle, sub_path_posix, mode, flags))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .TXTBSY => return error.FileBusy,
                    .NOTDIR => return error.FileNotFound,
                    .NOENT => return error.FileNotFound,
                    .NAMETOOLONG => return error.NameTooLong,
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.InputOutput,
                    .NOMEM => return error.SystemResources,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirCreateFile = switch (native_os) {
    .windows => windows_impl.dirCreateFileWindows,
    .wasi => wasi_impl.dirCreateFileWasi,
    else => dirCreateFilePosix,
};

fn dirCreateFilePosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.CreateFileOptions,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    var flags: posix.O = .{
        .ACCMODE = if (options.read) .RDWR else .WRONLY,
        .CREAT = true,
        .TRUNC = options.truncate,
        .EXCL = options.exclusive,
    };
    if (@hasField(posix.O, "LARGEFILE")) flags.LARGEFILE = true;
    if (@hasField(posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(posix.O, "RESOLVE_BENEATH")) flags.RESOLVE_BENEATH = options.resolve_beneath;

    // Use the O locking flags if the os supports them to acquire the lock
    // atomically. Note that the NONBLOCK flag is removed after the openat()
    // call is successful.
    if (have_flock_open_flags) switch (options.lock) {
        .none => {},
        .shared => {
            flags.SHLOCK = true;
            flags.NONBLOCK = options.lock_nonblocking;
        },
        .exclusive => {
            flags.EXLOCK = true;
            flags.NONBLOCK = options.lock_nonblocking;
        },
    };

    const fd: posix.fd_t = fd: {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = openat_sym(dir.handle, sub_path_posix, flags, options.permissions.toMode());
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break :fd @intCast(rc);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => return error.BadPathName,
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .ACCES => return error.AccessDenied,
                        .FBIG => return error.FileTooBig,
                        .OVERFLOW => return error.FileTooBig,
                        .ISDIR => return error.IsDir,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NODEV => return error.NoDevice,
                        .NOENT => return error.FileNotFound,
                        .SRCH => return error.FileNotFound, // Linux when accessing procfs.
                        .NOMEM => return error.SystemResources,
                        .NOSPC => return error.NoSpaceLeft,
                        .NOTDIR => return error.NotDir,
                        .PERM => return error.PermissionDenied,
                        .EXIST => return error.PathAlreadyExists,
                        .BUSY => return error.DeviceBusy,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        .AGAIN => return error.WouldBlock,
                        .TXTBSY => return error.FileBusy,
                        .NXIO => return error.NoDevice,
                        .ROFS => return error.ReadOnlyFileSystem,
                        .ILSEQ => return error.BadPathName,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };
    errdefer closeFd(fd);

    if (have_flock and !have_flock_open_flags and options.lock != .none) {
        const lock_nonblocking: i32 = if (options.lock_nonblocking) posix.LOCK.NB else 0;
        const lock_flags = switch (options.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        };

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.flock(fd, lock_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => |err| return errnoBug(err), // invalid parameters
                        .NOLCK => return error.SystemResources,
                        .AGAIN => return error.WouldBlock,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (have_flock_open_flags and options.lock_nonblocking) {
        var fl_flags: usize = fl: {
            const syscall: Syscall = try .start();
            while (true) {
                const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(u32, 0));
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break :fl @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |err| {
                        syscall.finish();
                        return posix.unexpectedErrno(err);
                    },
                }
            }
        };

        fl_flags &= ~@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, fl_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |err| {
                    syscall.finish();
                    return posix.unexpectedErrno(err);
                },
            }
        }
    }

    return .{
        .handle = fd,
        .flags = .{ .nonblocking = false },
    };
}

fn dirCreateFileAtomic(
    userdata: ?*anyopaque,
    dir: Dir,
    dest_path: []const u8,
    options: Dir.CreateFileAtomicOptions,
) Dir.CreateFileAtomicError!File.Atomic {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const t_io = io(t);

    // Linux has O_TMPFILE, but linkat() does not support AT_REPLACE, so it's
    // useless when we have to make up a bogus path name to do the rename()
    // anyway.
    if (native_os == .linux and !options.replace) tmpfile: {
        const flags: posix.O = if (@hasField(posix.O, "TMPFILE")) .{
            .ACCMODE = .RDWR,
            .TMPFILE = true,
            .DIRECTORY = true,
            .CLOEXEC = true,
        } else if (@hasField(posix.O, "TMPFILE0") and !@hasField(posix.O, "TMPFILE2")) .{
            .ACCMODE = .RDWR,
            .TMPFILE0 = true,
            .TMPFILE1 = true,
            .DIRECTORY = true,
            .CLOEXEC = true,
        } else break :tmpfile;

        const dest_dirname = Dir.path.dirname(dest_path);
        if (dest_dirname) |dirname| {
            // This has a nice side effect of preemptively triggering EISDIR or
            // ENOENT, avoiding the ambiguity below.
            if (options.make_path) dir.createDirPath(t_io, dirname) catch |err| switch (err) {
                // None of these make sense in this context.
                error.IsDir,
                error.Streaming,
                error.DiskQuota,
                error.PathAlreadyExists,
                error.LinkQuotaExceeded,
                error.PipeBusy,
                error.FileTooBig,
                error.DeviceBusy,
                error.FileLocksUnsupported,
                error.FileBusy,
                => return error.Unexpected,

                else => |e| return e,
            };
        }

        var path_buffer: [posix.PATH_MAX]u8 = undefined;
        const sub_path_posix = try pathToPosix(dest_dirname orelse ".", &path_buffer);

        const syscall: Syscall = try .start();
        while (true) {
            const rc = openat_sym(dir.handle, sub_path_posix, flags, options.permissions.toMode());
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    return .{
                        .file = .{
                            .handle = @intCast(rc),
                            .flags = .{ .nonblocking = false },
                        },
                        .file_basename_hex = 0,
                        .dest_sub_path = dest_path,
                        .file_open = true,
                        .file_exists = false,
                        .close_dir_on_deinit = false,
                        .dir = dir,
                    };
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                .ISDIR, .NOENT, .OPNOTSUPP => {
                    // Ambiguous error code. It might mean the file system
                    // does not support O_TMPFILE. Therefore, we must fall
                    // back to not using O_TMPFILE.
                    syscall.finish();
                    break :tmpfile;
                },
                .INVAL => return syscall.fail(error.BadPathName),
                .ACCES => return syscall.fail(error.AccessDenied),
                .LOOP => return syscall.fail(error.SymLinkLoop),
                .MFILE => return syscall.fail(error.ProcessFdQuotaExceeded),
                .NAMETOOLONG => return syscall.fail(error.NameTooLong),
                .NFILE => return syscall.fail(error.SystemFdQuotaExceeded),
                .NODEV => return syscall.fail(error.NoDevice),
                .NOMEM => return syscall.fail(error.SystemResources),
                .NOSPC => return syscall.fail(error.NoSpaceLeft),
                .NOTDIR => return syscall.fail(error.NotDir),
                .PERM => return syscall.fail(error.PermissionDenied),
                .AGAIN => return syscall.fail(error.WouldBlock),
                .NXIO => return syscall.fail(error.NoDevice),
                .ILSEQ => return syscall.fail(error.BadPathName),
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    }

    if (Dir.path.dirname(dest_path)) |dirname| {
        const new_dir = if (options.make_path)
            dir.createDirPathOpen(t_io, dirname, .{}) catch |err| switch (err) {
                // None of these make sense in this context.
                error.IsDir,
                error.Streaming,
                error.DiskQuota,
                error.PathAlreadyExists,
                error.LinkQuotaExceeded,
                error.PipeBusy,
                error.FileTooBig,
                error.FileLocksUnsupported,
                error.DeviceBusy,
                => return error.Unexpected,

                else => |e| return e,
            }
        else
            try dir.openDir(t_io, dirname, .{});

        return atomicFileInit(t_io, Dir.path.basename(dest_path), options.permissions, new_dir, true);
    }

    return atomicFileInit(t_io, dest_path, options.permissions, dir, false);
}

fn atomicFileInit(
    t_io: Io,
    dest_basename: []const u8,
    permissions: File.Permissions,
    dir: Dir,
    close_dir_on_deinit: bool,
) Dir.CreateFileAtomicError!File.Atomic {
    while (true) {
        var random_integer: u64 = undefined;
        t_io.random(@ptrCast(&random_integer));
        const tmp_sub_path = std.fmt.hex(random_integer);
        const file = dir.createFile(t_io, &tmp_sub_path, .{
            .permissions = permissions,
            .exclusive = true,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            error.DeviceBusy => continue,
            error.FileBusy => continue,

            error.IsDir => return error.Unexpected, // No path components.
            error.FileTooBig => return error.Unexpected, // Creating, not opening.
            error.FileLocksUnsupported => return error.Unexpected, // Not asking for locks.
            error.PipeBusy => return error.Unexpected, // Not opening a pipe.

            else => |e| return e,
        };
        return .{
            .file = file,
            .file_basename_hex = random_integer,
            .dest_sub_path = dest_basename,
            .file_open = true,
            .file_exists = true,
            .close_dir_on_deinit = close_dir_on_deinit,
            .dir = dir,
        };
    }
}

pub const dirOpenFile = switch (native_os) {
    .windows => windows_impl.dirOpenFileWindows,
    .wasi => wasi_impl.dirOpenFileWasi,
    else => dirOpenFilePosix,
};

pub fn dirOpenFilePosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.OpenFileOptions,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    var flags: posix.O = switch (native_os) {
        .wasi => .{
            .read = options.mode != .write_only,
            .write = options.mode != .read_only,
            .NOFOLLOW = !options.follow_symlinks,
        },
        else => .{
            .ACCMODE = switch (options.mode) {
                .read_only => .RDONLY,
                .write_only => .WRONLY,
                .read_write => .RDWR,
            },
            .NOFOLLOW = !options.follow_symlinks,
        },
    };
    if (@hasField(posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(posix.O, "LARGEFILE")) flags.LARGEFILE = true;
    if (@hasField(posix.O, "NOCTTY")) flags.NOCTTY = !options.allow_ctty;
    if (@hasField(posix.O, "PATH")) flags.PATH = options.path_only;
    if (@hasField(posix.O, "RESOLVE_BENEATH")) flags.RESOLVE_BENEATH = options.resolve_beneath;

    // Use the O locking options if the os supports them to acquire the lock
    // atomically. Note that the NONBLOCK flag is removed after the openat()
    // call is successful.
    if (have_flock_open_flags) switch (options.lock) {
        .none => {},
        .shared => {
            flags.SHLOCK = true;
            flags.NONBLOCK = options.lock_nonblocking;
        },
        .exclusive => {
            flags.EXLOCK = true;
            flags.NONBLOCK = options.lock_nonblocking;
        },
    };

    const mode: posix.mode_t = 0;

    const fd: posix.fd_t = fd: {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = openat_sym(dir.handle, sub_path_posix, flags, mode);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break :fd @intCast(rc);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => return error.BadPathName,
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .ACCES => return error.AccessDenied,
                        .FBIG => return error.FileTooBig,
                        .OVERFLOW => return error.FileTooBig,
                        .ISDIR => return error.IsDir,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NODEV => return error.NoDevice,
                        .NOENT => return error.FileNotFound,
                        .SRCH => return error.FileNotFound, // Linux when opening procfs files.
                        .NOMEM => return error.SystemResources,
                        .NOSPC => return error.NoSpaceLeft,
                        .NOTDIR => return error.NotDir,
                        .PERM => return error.PermissionDenied,
                        .EXIST => return error.PathAlreadyExists,
                        .BUSY => return error.DeviceBusy,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        .AGAIN => return error.WouldBlock,
                        .TXTBSY => return error.FileBusy,
                        .NXIO => return error.NoDevice,
                        .ROFS => return error.ReadOnlyFileSystem,
                        .ILSEQ => return error.BadPathName,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };
    errdefer closeFd(fd);

    if (!options.allow_directory) {
        const is_dir = is_dir: {
            const stat = fileStat(t, .{
                .handle = fd,
                .flags = .{ .nonblocking = false },
            }) catch |err| switch (err) {
                // The directory-ness is either unknown or unknowable
                error.Streaming => break :is_dir false,
                else => |e| return e,
            };
            break :is_dir stat.kind == .directory;
        };
        if (is_dir) return error.IsDir;
    }

    if (have_flock and !have_flock_open_flags and options.lock != .none) {
        const lock_nonblocking: i32 = if (options.lock_nonblocking) posix.LOCK.NB else 0;
        const lock_flags = switch (options.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        };
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.flock(fd, lock_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => |err| return errnoBug(err), // invalid parameters
                        .NOLCK => return error.SystemResources,
                        .AGAIN => return error.WouldBlock,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (have_flock_open_flags and options.lock_nonblocking) {
        var fl_flags: usize = fl: {
            const syscall: Syscall = try .start();
            while (true) {
                const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(u32, 0));
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break :fl @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |err| {
                        syscall.finish();
                        return posix.unexpectedErrno(err);
                    },
                }
            }
        };

        fl_flags &= ~@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, fl_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |err| {
                    syscall.finish();
                    return posix.unexpectedErrno(err);
                },
            }
        }
    }

    return .{
        .handle = fd,
        .flags = .{ .nonblocking = false },
    };
}

pub const dirOpenFileWtf16 = windows_impl.dirOpenFileWtf16;
const dirOpenDir = switch (native_os) {
    .wasi => wasi_impl.dirOpenDirWasi,
    .haiku => dirOpenDirHaiku,
    else => dirOpenDirPosix,
};

/// This function is also used for WASI when libc is linked.
pub fn dirOpenDirPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const sub_path_w = try windows_impl.sliceToPrefixedFileW(dir.handle, sub_path, .{});
        return windows_impl.dirOpenDirWindows(dir, sub_path_w.span(), options);
    }

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    var flags: posix.O = switch (native_os) {
        .wasi => .{
            .read = true,
            .NOFOLLOW = !options.follow_symlinks,
            .DIRECTORY = true,
        },
        else => .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = !options.follow_symlinks,
            .DIRECTORY = true,
            .CLOEXEC = true,
        },
    };

    if (@hasField(posix.O, "PATH") and !options.iterate)
        flags.PATH = true;

    const mode: posix.mode_t = 0;

    const syscall: Syscall = try .start();
    while (true) {
        const rc = openat_sym(dir.handle, sub_path_posix, flags, mode);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return .{ .handle = @intCast(rc) };
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .INVAL => return syscall.fail(error.BadPathName),
            .ACCES => return syscall.fail(error.AccessDenied),
            .LOOP => return syscall.fail(error.SymLinkLoop),
            .MFILE => return syscall.fail(error.ProcessFdQuotaExceeded),
            .NAMETOOLONG => return syscall.fail(error.NameTooLong),
            .NFILE => return syscall.fail(error.SystemFdQuotaExceeded),
            .NODEV => return syscall.fail(error.NoDevice),
            .NOENT => return syscall.fail(error.FileNotFound),
            .NOMEM => return syscall.fail(error.SystemResources),
            .NOTDIR => return syscall.fail(error.NotDir),
            .PERM => return syscall.fail(error.PermissionDenied),
            .NXIO => return syscall.fail(error.NoDevice),
            .ILSEQ => return syscall.fail(error.BadPathName),
            .FAULT => |err| return syscall.errnoBug(err),
            .BADF => |err| return syscall.errnoBug(err), // File descriptor used after closed.
            .BUSY => |err| return syscall.errnoBug(err), // O_EXCL not passed
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

fn dirOpenDirHaiku(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    _ = options;

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system._kern_open_dir(dir.handle, sub_path_posix);
        if (rc >= 0) {
            syscall.finish();
            return .{ .handle = rc };
        }
        switch (@as(posix.E, @fromBackingInt(@intCast(rc)))) {
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .BUSY => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub const dirOpenDirWindows = windows_impl.dirOpenDirWindows;
fn dirClose(userdata: ?*anyopaque, dirs: []const Dir) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    for (dirs) |dir| {
        if (is_windows) {
            windows.CloseHandle(dir.handle);
        } else {
            closeFd(dir.handle);
        }
    }
}

const dirRead = switch (native_os) {
    .linux => if (is_yasos) dirReadYasos else dirReadLinux,
    .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => darwin_impl.dirReadDarwin,
    .freebsd, .netbsd, .dragonfly, .openbsd => dirReadBsd,
    .illumos => dirReadIllumos,
    .haiku => dirReadHaiku,
    .windows => windows_impl.dirReadWindows,
    .wasi => wasi_impl.dirReadWasi,
    else => dirReadUnimplemented,
};

fn dirReadLinux(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const linux = std.os.linux;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable => return error.Unexpected,
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const n = while (true) {
                const rc = linux.getdents64(dr.dir.handle, dr.buffer.ptr, @min(dr.buffer.len, std.math.maxInt(c_uint)));
                switch (linux.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break rc;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability.
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            // To be consistent across platforms, iteration
                            // ends if the directory being iterated is deleted
                            // during iteration. This matches the behavior of
                            // non-Linux, non-WASI UNIX platforms.
                            .NOENT => {
                                dr.state = .finished;
                                return 0;
                            },
                            // This can occur when reading /proc/$PID/net, or
                            // if the provided buffer is too small. Neither
                            // scenario is intended to be handled by this API.
                            .INVAL => return error.Unexpected,
                            .ACCES => return error.AccessDenied, // Lacking permission to iterate this directory.
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = n;
        }
        // Linux aligns the header by padding after the null byte of the name
        // to align the next entry. This means we can find the end of the name
        // by looking at only the 8 bytes before the next record. However since
        // file names are usually short it's better to keep the machine code
        // simpler.
        //
        // Furthermore, I observed qemu user mode to not align this struct, so
        // this code makes the conservative choice to not assume alignment.
        const linux_entry: *align(1) linux.dirent64 = @ptrCast(&dr.buffer[dr.index]);
        const next_index = dr.index + linux_entry.reclen;
        dr.index = next_index;
        const name_ptr: [*]u8 = &linux_entry.name;
        const padded_name = name_ptr[0 .. linux_entry.reclen - @offsetOf(linux.dirent64, "name")];
        const name_len = std.mem.findScalar(u8, padded_name, 0).?;
        const name = name_ptr[0..name_len :0];

        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        const entry_kind: File.Kind = switch (linux_entry.type) {
            linux.DT.BLK => .block_device,
            linux.DT.CHR => .character_device,
            linux.DT.DIR => .directory,
            linux.DT.FIFO => .named_pipe,
            linux.DT.LNK => .sym_link,
            linux.DT.REG => .file,
            linux.DT.SOCK => .unix_domain_socket,
            else => .unknown,
        };
        buffer[buffer_index] = .{
            .name = name,
            .kind = entry_kind,
            .inode = linux_entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

/// YasOS: `getdents` of its libc -- a raw Linux system call is not a YasOS one -- which
/// hands back one record per call, in YasOS's layout (32-bit inode and offset, then
/// Linux's fields) with YasOS's `DT_` numbers.  The end of the directory is a result
/// of 0 or less.
fn dirReadYasos(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const Dirent = extern struct {
        ino: c_ulong,
        off: c_ulong,
        reclen: c_ushort,
        type: u8,
        name: [256]u8,
    };
    const DT = struct {
        const BLK = 1;
        const CHR = 2;
        const DIR = 3;
        const FIFO = 4;
        const LNK = 5;
        const REG = 6;
        const SOCK = 7;
    };
    const getdents = @extern(*const fn (fd: c_int, buf: [*]u8, len: usize) callconv(.c) isize, .{ .name = "getdents" });
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                // A directory just opened is at its start; one the kernel cannot seek
                // is read from where it is.
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable, error.Unexpected => {},
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const rc = getdents(dr.dir.handle, dr.buffer.ptr, dr.buffer.len);
            syscall.finish();
            if (rc <= 0) {
                dr.state = .finished;
                return buffer_index;
            }
            dr.index = 0;
            dr.end = @intCast(rc);
        }
        const start = dr.index;
        const entry: *align(1) Dirent = @ptrCast(&dr.buffer[start]);
        dr.index = @min(dr.end, start + @max(entry.reclen, @offsetOf(Dirent, "name") + 1));
        const name_ptr: [*]u8 = &entry.name;
        const room = @min(entry.name.len, dr.end - start - @offsetOf(Dirent, "name"));
        const name_len = std.mem.findScalar(u8, name_ptr[0..room], 0) orelse return error.Unexpected;
        const name = name_ptr[0..name_len :0];
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        buffer[buffer_index] = .{
            .name = name,
            .kind = switch (entry.type) {
                DT.BLK => .block_device,
                DT.CHR => .character_device,
                DT.DIR => .directory,
                DT.FIFO => .named_pipe,
                DT.LNK => .sym_link,
                DT.REG => .file,
                DT.SOCK => .unix_domain_socket,
                else => .unknown,
            },
            .inode = entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadBsd(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable => return error.Unexpected,
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const n: usize = while (true) {
                const rc = posix.system.getdents(dr.dir.handle, dr.buffer.ptr, dr.buffer.len);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            .INVAL => |err| return errnoBug(err),
                            // Introduced in freebsd 13.2: directory unlinked
                            // but still open. To be consistent, iteration ends
                            // if the directory being iterated is deleted
                            // during iteration.
                            .NOENT => {
                                dr.state = .finished;
                                return 0;
                            },
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = n;
        }
        const bsd_entry = @as(*align(1) posix.system.dirent, @ptrCast(&dr.buffer[dr.index]));
        const next_index = dr.index +
            if (@hasField(posix.system.dirent, "reclen")) bsd_entry.reclen else bsd_entry.reclen();
        dr.index = next_index;

        const name = @as([*]u8, @ptrCast(&bsd_entry.name))[0..bsd_entry.namlen];

        const skip_zero_fileno = switch (native_os) {
            // fileno=0 is used to mark invalid entries or deleted files.
            .openbsd, .netbsd => true,
            else => false,
        };
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or
            (skip_zero_fileno and bsd_entry.fileno == 0))
        {
            continue;
        }

        const entry_kind: File.Kind = switch (bsd_entry.type) {
            posix.DT.BLK => .block_device,
            posix.DT.CHR => .character_device,
            posix.DT.DIR => .directory,
            posix.DT.FIFO => .named_pipe,
            posix.DT.LNK => .sym_link,
            posix.DT.REG => .file,
            posix.DT.SOCK => .unix_domain_socket,
            posix.DT.WHT => .whiteout,
            else => .unknown,
        };
        buffer[buffer_index] = .{
            .name = name,
            .kind = entry_kind,
            .inode = bsd_entry.fileno,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadIllumos(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable => return error.Unexpected,
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const n: usize = while (true) {
                const rc = posix.system.getdents(dr.dir.handle, dr.buffer.ptr, dr.buffer.len);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break rc;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            .INVAL => |err| return errnoBug(err),
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = n;
        }
        const entry = @as(*align(1) posix.system.dirent, @ptrCast(&dr.buffer[dr.index]));
        const next_index = dr.index + entry.reclen;
        dr.index = next_index;

        const name = std.mem.sliceTo(@as([*:0]u8, @ptrCast(&entry.name)), 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        // illumos dirent doesn't expose type, so we have to call stat to get it.
        const stat = try posixStatFile(dr.dir.handle, name, posix.AT.SYMLINK_NOFOLLOW);

        buffer[buffer_index] = .{
            .name = name,
            .kind = stat.kind,
            .inode = entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadHaiku(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = posix.system._kern_rewind_dir(dr.dir.handle);
                    switch (@as(posix.E, @fromBackingInt(@intCast(@min(rc, 0))))) {
                        .SUCCESS => {
                            syscall.finish();
                            break;
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        else => |e| {
                            syscall.finish();
                            switch (e) {
                                else => |err| return posix.unexpectedErrno(err),
                            }
                        },
                    }
                }
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const n: usize = while (true) {
                const rc = posix.system._kern_read_dir(dr.dir.handle, dr.buffer.ptr, dr.buffer.len, @truncate(dr.buffer.len / @sizeOf(posix.system.DirEnt)));
                switch (@as(posix.E, @fromBackingInt(@intCast(@min(rc, 0))))) {
                    .SUCCESS => {
                        syscall.finish();
                        break @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            // _kern_read_dir returns entry count, but Dir.Reader is designed for byte count
            dr.end = 0;
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const entry = @as(*align(1) posix.system.DirEnt, @ptrCast(&dr.buffer[dr.end]));
                dr.end += entry.reclen;
            }
        }
        const entry = @as(*align(1) posix.system.DirEnt, @ptrCast(&dr.buffer[dr.index]));
        const next_index = dr.index + entry.reclen;
        dr.index = next_index;

        const name = std.mem.sliceTo(@as([*:0]u8, @ptrCast(&entry.name)), 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or entry.ino == 0) continue;

        // haiku dirent doesn't expose type, so we have to call stat to get it.
        var stat: std.c.Stat = undefined;
        {
            const syscall: Syscall = try .start();
            while (true) {
                const rc = posix.system._kern_read_stat(dr.dir.handle, name, false, &stat, @sizeOf(std.c.Stat));
                switch (@as(posix.E, @fromBackingInt(@intCast(@min(rc, 0))))) {
                    .SUCCESS => {
                        syscall.finish();
                        break;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
        }

        const entry_kind: File.Kind = switch (stat.mode & posix.S.IFMT) {
            posix.S.IFBLK => .block_device,
            posix.S.IFCHR => .character_device,
            posix.S.IFDIR => .directory,
            posix.S.IFIFO => .named_pipe,
            posix.S.IFLNK => .sym_link,
            posix.S.IFREG => .file,
            else => .unknown,
        };
        buffer[buffer_index] = .{
            .name = name,
            .kind = entry_kind,
            .inode = entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadUnimplemented(userdata: ?*anyopaque, dir_reader: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    _ = userdata;
    _ = dir_reader;
    _ = buffer;
    return error.Unexpected;
}

const dirRealPathFile = switch (native_os) {
    .windows => windows_impl.dirRealPathFileWindows,
    else => dirRealPathFilePosix,
};

pub const GetFinalPathNameByHandleFormat = windows_impl.GetFinalPathNameByHandleFormat;
pub const GetFinalPathNameByHandleError = windows_impl.GetFinalPathNameByHandleError;
pub const GetFinalPathNameByHandle = windows_impl.GetFinalPathNameByHandle;
pub const QueryObjectNameError = windows_impl.QueryObjectNameError;
pub const QueryObjectName = windows_impl.QueryObjectName;
pub const wToPrefixedFileW = windows_impl.wToPrefixedFileW;
pub const Wtf8ToPrefixedFileWError = windows_impl.Wtf16ToPrefixedFileWError;

pub const sliceToPrefixedFileW = windows_impl.sliceToPrefixedFileW;
pub const WindowsPathSpace = windows_impl.WindowsPathSpace;
fn dirRealPathFilePosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, out_buffer: []u8) Dir.RealPathFileError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    if (builtin.link_libc and dir.handle == posix.AT.FDCWD) {
        if (out_buffer.len < posix.PATH_MAX) return error.NameTooLong;
        const syscall: Syscall = try .start();
        while (true) {
            if (std.c.realpath(sub_path_posix, out_buffer.ptr)) |redundant_pointer| {
                syscall.finish();
                assert(redundant_pointer == out_buffer.ptr);
                return std.mem.findScalar(u8, out_buffer, 0) orelse out_buffer.len;
            }
            const err: posix.E = @fromBackingInt(@intCast(std.c._errno().*));
            if (err == .INTR) {
                try syscall.checkCancel();
                continue;
            }
            syscall.finish();
            switch (err) {
                .INVAL => return errnoBug(err),
                .BADF => return errnoBug(err),
                .FAULT => return errnoBug(err),
                .ACCES => return error.AccessDenied,
                .NOENT => return error.FileNotFound,
                .OPNOTSUPP => return error.OperationUnsupported,
                .NOTDIR => return error.NotDir,
                .NAMETOOLONG => return error.NameTooLong,
                .LOOP => return error.SymLinkLoop,
                .IO => return error.InputOutput,
                else => return posix.unexpectedErrno(err),
            }
        }
    }

    var flags: posix.O = .{};
    if (@hasField(posix.O, "NONBLOCK")) flags.NONBLOCK = true;
    if (@hasField(posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(posix.O, "PATH")) flags.PATH = true;

    const mode: posix.mode_t = 0;

    const syscall: Syscall = try .start();
    const fd: posix.fd_t = while (true) {
        const rc = openat_sym(dir.handle, sub_path_posix, flags, mode);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                break @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.BadPathName,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .FBIG => return error.FileTooBig,
                    .OVERFLOW => return error.FileTooBig,
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .SRCH => return error.FileNotFound, // Linux when accessing procfs.
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .EXIST => return error.PathAlreadyExists,
                    .BUSY => return error.DeviceBusy,
                    .NXIO => return error.NoDevice,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    };
    defer closeFd(fd);
    return realPathPosix(fd, out_buffer);
}

const dirRealPath = switch (native_os) {
    .windows => windows_impl.dirRealPathWindows,
    else => dirRealPathPosix,
};

fn dirRealPathPosix(userdata: ?*anyopaque, dir: Dir, out_buffer: []u8) Dir.RealPathError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathPosix(dir.handle, out_buffer);
}

const fileRealPath = switch (native_os) {
    .windows => windows_impl.fileRealPathWindows,
    else => fileRealPathPosix,
};

fn fileRealPathPosix(userdata: ?*anyopaque, file: File, out_buffer: []u8) File.RealPathError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathPosix(file.handle, out_buffer);
}

pub fn realPathPosix(fd: posix.fd_t, out_buffer: []u8) File.RealPathError!usize {
    if (fd == posix.AT.FDCWD) return processCurrentPathPosix(out_buffer) catch |err| switch (err) {
        else => |e| return e,
        error.CurrentDirUnlinked => return error.FileNotFound,
        error.PathExceedsLimit => return error.NameTooLong,
    };
    switch (native_os) {
        .dragonfly, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
            var sufficient_buffer: [posix.PATH_MAX]u8 = undefined;
            @memset(&sufficient_buffer, 0);
            const syscall: Syscall = try .start();
            while (true) {
                switch (posix.errno(posix.system.fcntl(fd, posix.F.GETPATH, &sufficient_buffer))) {
                    .SUCCESS => {
                        syscall.finish();
                        break;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .ACCES => return error.AccessDenied,
                            .BADF => return error.FileNotFound,
                            .NOENT => return error.FileNotFound,
                            .NOMEM => return error.SystemResources,
                            .NOSPC => return error.NameTooLong,
                            .RANGE => return error.NameTooLong,
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
            const n = std.mem.findScalar(u8, &sufficient_buffer, 0) orelse sufficient_buffer.len;
            if (n > out_buffer.len) return error.NameTooLong;
            @memcpy(out_buffer[0..n], sufficient_buffer[0..n]);
            return n;
        },
        .linux, .serenity, .illumos => {
            var procfs_buf: ["/proc/self/path/-2147483648\x00".len]u8 = undefined;
            const template = if (native_os == .illumos) "/proc/self/path/{d}" else "/proc/self/fd/{d}";
            const proc_path = std.mem.printSentinel(&procfs_buf, template, .{fd}, 0) catch unreachable;
            const syscall: Syscall = try .start();
            while (true) {
                const rc = posix.system.readlink(proc_path, out_buffer.ptr, out_buffer.len);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        const len: usize = @bitCast(rc);
                        return len;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .ACCES => return error.AccessDenied,
                            .FAULT => |err| return errnoBug(err),
                            .IO => return error.FileSystem,
                            .LOOP => return error.SymLinkLoop,
                            .NAMETOOLONG => return error.NameTooLong,
                            .NOENT => return error.FileNotFound,
                            .NOMEM => return error.SystemResources,
                            .NOTDIR => return error.NotDir,
                            .ILSEQ => |err| return errnoBug(err),
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
        },
        .freebsd => {
            var k_file: std.c.kinfo_file = undefined;
            k_file.structsize = std.c.KINFO_FILE_SIZE;
            const syscall: Syscall = try .start();
            while (true) {
                switch (posix.errno(std.c.fcntl(fd, std.c.F.KINFO, @intFromPtr(&k_file)))) {
                    .SUCCESS => {
                        syscall.finish();
                        break;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    .BADF => {
                        syscall.finish();
                        return error.FileNotFound;
                    },
                    else => |err| {
                        syscall.finish();
                        return posix.unexpectedErrno(err);
                    },
                }
            }
            const len = std.mem.findScalar(u8, &k_file.path, 0) orelse k_file.path.len;
            if (len == 0) return error.NameTooLong;
            @memcpy(out_buffer[0..len], k_file.path[0..len]);
            return len;
        },
        else => return error.OperationUnsupported,
    }
    comptime unreachable;
}

fn fileHardLink(
    userdata: ?*anyopaque,
    file: File,
    new_dir: Dir,
    new_sub_path: []const u8,
    options: File.HardLinkOptions,
) File.HardLinkError!void {
    _ = userdata;
    if (native_os != .linux) return error.OperationUnsupported;

    var new_path_buffer: [posix.PATH_MAX]u8 = undefined;
    const new_sub_path_posix = try pathToPosix(new_sub_path, &new_path_buffer);

    const flags: u32 = if (options.follow_symlinks)
        posix.AT.SYMLINK_FOLLOW | posix.AT.EMPTY_PATH
    else
        posix.AT.EMPTY_PATH;

    return linkat(file.handle, "", new_dir.handle, new_sub_path_posix, flags) catch |err| switch (err) {
        error.FileNotFound => {
            if (options.follow_symlinks) return error.FileNotFound;
            var proc_buf: ["/proc/self/fd/-2147483648\x00".len]u8 = undefined;
            const proc_path = std.mem.printSentinel(&proc_buf, "/proc/self/fd/{d}", .{file.handle}, 0) catch
                unreachable;
            return linkat(posix.AT.FDCWD, proc_path, new_dir.handle, new_sub_path_posix, posix.AT.SYMLINK_FOLLOW);
        },
        else => |e| return e,
    };
}

fn linkat(
    old_dir: posix.fd_t,
    old_path: [*:0]const u8,
    new_dir: posix.fd_t,
    new_path: [*:0]const u8,
    flags: u32,
) File.HardLinkError!void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.linkat(old_dir, old_path, new_dir, new_path, flags))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ACCES => return syscall.fail(error.AccessDenied),
            .DQUOT => return syscall.fail(error.DiskQuota),
            .EXIST => return syscall.fail(error.PathAlreadyExists),
            .IO => return syscall.fail(error.HardwareFailure),
            .LOOP => return syscall.fail(error.SymLinkLoop),
            .MLINK => return syscall.fail(error.LinkQuotaExceeded),
            .NAMETOOLONG => return syscall.fail(error.NameTooLong),
            .NOENT => return syscall.fail(error.FileNotFound),
            .NOMEM => return syscall.fail(error.SystemResources),
            .NOSPC => return syscall.fail(error.NoSpaceLeft),
            .NOTDIR => return syscall.fail(error.NotDir),
            .PERM => return syscall.fail(error.PermissionDenied),
            .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
            .XDEV => return syscall.fail(error.CrossDevice),
            .ILSEQ => return syscall.fail(error.BadPathName),
            .FAULT => |err| return syscall.errnoBug(err),
            .INVAL => |err| return syscall.errnoBug(err),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

const dirDeleteFile = switch (native_os) {
    .windows => windows_impl.dirDeleteFileWindows,
    .wasi => wasi_impl.dirDeleteFileWasi,
    else => dirDeleteFilePosix,
};

pub fn dirDeleteFilePosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteFileError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.unlinkat(dir.handle, sub_path_posix, 0))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            // Some systems return permission errors when trying to delete a
            // directory, so we need to handle that case specifically and
            // translate the error.
            .PERM => switch (native_os) {
                .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos, .freebsd, .netbsd, .dragonfly, .openbsd, .illumos => {

                    // Don't follow symlinks to match unlinkat (which acts on symlinks rather than follows them).
                    var st = std.mem.zeroes(posix.Stat);
                    while (true) {
                        try syscall.checkCancel();
                        switch (posix.errno(fstatat_sym(dir.handle, sub_path_posix, &st, posix.AT.SYMLINK_NOFOLLOW))) {
                            .SUCCESS => {
                                syscall.finish();
                                break;
                            },
                            .INTR => continue,
                            else => {
                                syscall.finish();
                                return error.PermissionDenied;
                            },
                        }
                    }
                    const is_dir = st.mode & posix.S.IFMT == posix.S.IFDIR;
                    if (is_dir)
                        return error.IsDir
                    else
                        return error.PermissionDenied;
                },
                else => {
                    syscall.finish();
                    return error.PermissionDenied;
                },
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .BUSY => return error.FileBusy,
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.FileSystem,
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .EXIST => |err| return errnoBug(err),
                    .NOTEMPTY => |err| return errnoBug(err), // Not passing AT.REMOVEDIR
                    .ILSEQ => return error.BadPathName,
                    .INVAL => |err| return errnoBug(err), // invalid flags, or pathname has . as last component
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirDeleteDir = switch (native_os) {
    .windows => windows_impl.dirDeleteDirWindows,
    .wasi => wasi_impl.dirDeleteDirWasi,
    else => dirDeleteDirPosix,
};

pub fn dirDeleteDirPosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteDirError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.unlinkat(dir.handle, sub_path_posix, posix.AT.REMOVEDIR))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.FileBusy,
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.FileSystem,
                    .ISDIR => |err| return errnoBug(err),
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .EXIST => |err| return errnoBug(err),
                    .NOTEMPTY => return error.DirNotEmpty,
                    .ILSEQ => return error.BadPathName,
                    .INVAL => |err| return errnoBug(err), // invalid flags, or pathname has . as last component
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirRename = switch (native_os) {
    .windows => windows_impl.dirRenameWindows,
    .wasi => wasi_impl.dirRenameWasi,
    else => dirRenamePosix,
};

fn dirRenamePreserve(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenamePreserveError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (is_windows) return windows_impl.dirRenameWindowsInner(old_dir, old_sub_path, new_dir, new_sub_path, false);
    if (is_darwin) return darwin_impl.dirRenamePreserveDarwin(old_dir, old_sub_path, new_dir, new_sub_path);
    if (native_os == .linux) {
        if (dirRenamePreserveLinux(old_dir, old_sub_path, new_dir, new_sub_path)) |_| {
            return;
        } else |err| switch (err) {
            else => |e| return e,
            error.OperationUnsupported => {}, // Fall back to link/unlink below.
        }
    }
    // Make a hard link then delete the original.
    try dirHardLink(t, old_dir, old_sub_path, new_dir, new_sub_path, .{ .follow_symlinks = false });
    const prev = swapCancelProtection(t, .blocked);
    defer _ = swapCancelProtection(t, prev);
    dirDeleteFile(t, old_dir, old_sub_path) catch {};
}

pub fn dirRenamePosix(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenameError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var old_path_buffer: [posix.PATH_MAX]u8 = undefined;
    var new_path_buffer: [posix.PATH_MAX]u8 = undefined;

    const old_sub_path_posix = try pathToPosix(old_sub_path, &old_path_buffer);
    const new_sub_path_posix = try pathToPosix(new_sub_path, &new_path_buffer);

    return renameat(old_dir.handle, old_sub_path_posix, new_dir.handle, new_sub_path_posix);
}

fn dirRenamePreserveLinux(
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenamePreserveError!void {
    const linux = std.os.linux;

    var old_path_buffer: [linux.PATH_MAX]u8 = undefined;
    var new_path_buffer: [linux.PATH_MAX]u8 = undefined;

    const old_sub_path_posix = try pathToPosix(old_sub_path, &old_path_buffer);
    const new_sub_path_posix = try pathToPosix(new_sub_path, &new_path_buffer);

    const syscall: Syscall = try .start();
    while (true) switch (linux.errno(linux.renameat2(
        old_dir.handle,
        old_sub_path_posix,
        new_dir.handle,
        new_sub_path_posix,
        .{ .NOREPLACE = true },
    ))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .ACCES => return syscall.fail(error.AccessDenied),
        .PERM => return syscall.fail(error.PermissionDenied),
        .BUSY => return syscall.fail(error.FileBusy),
        .DQUOT => return syscall.fail(error.DiskQuota),
        .ISDIR => return syscall.fail(error.IsDir),
        .LOOP => return syscall.fail(error.SymLinkLoop),
        .MLINK => return syscall.fail(error.LinkQuotaExceeded),
        .NAMETOOLONG => return syscall.fail(error.NameTooLong),
        .NOENT => return syscall.fail(error.FileNotFound),
        .NOTDIR => return syscall.fail(error.NotDir),
        .NOMEM => return syscall.fail(error.SystemResources),
        .NOSPC => return syscall.fail(error.NoSpaceLeft),
        .EXIST => return syscall.fail(error.PathAlreadyExists),
        .NOTEMPTY => return syscall.fail(error.DirNotEmpty),
        .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
        .XDEV => return syscall.fail(error.CrossDevice),
        .ILSEQ => return syscall.fail(error.BadPathName),
        // EINVAL when passing NOREPLACE=true observed on ext4, 7.0.0-38-generic #38~24.04.4-Ubuntu.
        // OPNOTSUPP handled defensively.
        .INVAL, .OPNOTSUPP => return syscall.fail(error.OperationUnsupported),
        .FAULT => |err| return syscall.errnoBug(err),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

fn renameat(
    old_dir: posix.fd_t,
    old_sub_path: [*:0]const u8,
    new_dir: posix.fd_t,
    new_sub_path: [*:0]const u8,
) Dir.RenameError!void {
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.renameat(old_dir, old_sub_path, new_dir, new_sub_path))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .ACCES => return syscall.fail(error.AccessDenied),
        .PERM => return syscall.fail(error.PermissionDenied),
        .BUSY => return syscall.fail(error.FileBusy),
        .DQUOT => return syscall.fail(error.DiskQuota),
        .ISDIR => return syscall.fail(error.IsDir),
        .IO => return syscall.fail(error.HardwareFailure),
        .LOOP => return syscall.fail(error.SymLinkLoop),
        .MLINK => return syscall.fail(error.LinkQuotaExceeded),
        .NAMETOOLONG => return syscall.fail(error.NameTooLong),
        .NOENT => return syscall.fail(error.FileNotFound),
        .NOTDIR => return syscall.fail(error.NotDir),
        .NOMEM => return syscall.fail(error.SystemResources),
        .NOSPC => return syscall.fail(error.NoSpaceLeft),
        .EXIST => return syscall.fail(error.DirNotEmpty),
        .NOTEMPTY => return syscall.fail(error.DirNotEmpty),
        .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
        .XDEV => return syscall.fail(error.CrossDevice),
        .ILSEQ => return syscall.fail(error.BadPathName),
        .FAULT => |err| return syscall.errnoBug(err),
        .INVAL => |err| return syscall.errnoBug(err),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

const dirSymLink = switch (native_os) {
    .windows => windows_impl.dirSymLinkWindows,
    .wasi => wasi_impl.dirSymLinkWasi,
    else => dirSymLinkPosix,
};

pub fn dirSymLinkPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: Dir.SymLinkFlags,
) Dir.SymLinkError!void {
    _ = flags;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var target_path_buffer: [posix.PATH_MAX]u8 = undefined;
    var sym_link_path_buffer: [posix.PATH_MAX]u8 = undefined;

    const target_path_posix = try pathToPosix(target_path, &target_path_buffer);
    const sym_link_path_posix = try pathToPosix(sym_link_path, &sym_link_path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.symlinkat(target_path_posix, dir.handle, sym_link_path_posix))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .DQUOT => return error.DiskQuota,
                    .EXIST => return error.PathAlreadyExists,
                    .IO => return error.FileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirReadLink(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    switch (native_os) {
        .windows => return windows_impl.dirReadLinkWindows(dir, sub_path, buffer),
        .wasi => return wasi_impl.dirReadLinkWasi(dir, sub_path, buffer),
        else => return dirReadLinkPosix(dir, sub_path, buffer),
    }
}

pub fn dirReadLinkPosix(dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    var sub_path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &sub_path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.readlinkat(dir.handle, sub_path_posix, buffer.ptr, buffer.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const len: usize = @bitCast(rc);
                return len;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.NotLink,
                    .IO => return error.FileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirSetPermissions = switch (native_os) {
    .windows => windows_impl.dirSetPermissionsWindows,
    else => dirSetPermissionsPosix,
};

fn dirSetPermissionsPosix(userdata: ?*anyopaque, dir: Dir, permissions: Dir.Permissions) Dir.SetPermissionsError!void {
    if (@sizeOf(Dir.Permissions) == 0) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return setPermissionsPosix(dir.handle, permissions.toMode());
}

fn dirSetFilePermissions(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.SetFilePermissionsOptions,
) Dir.SetFilePermissionsError!void {
    if (@sizeOf(Dir.Permissions) == 0) return;
    if (is_windows) @panic("TODO implement dirSetFilePermissions windows");
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const mode = permissions.toMode();
    const flags: u32 = if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0;

    return posixFchmodat(t, dir.handle, sub_path_posix, mode, flags);
}

fn posixFchmodat(
    t: *Threaded,
    dir_fd: posix.fd_t,
    path: [*:0]const u8,
    mode: posix.mode_t,
    flags: u32,
) Dir.SetFilePermissionsError!void {
    // No special handling for linux is needed if we can use the libc fallback
    // or `flags` is empty. Glibc only added the fallback in 2.32.
    if (have_fchmodat_flags or flags == 0) {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = if (have_fchmodat_flags or builtin.link_libc)
                posix.system.fchmodat(dir_fd, path, mode, flags)
            else
                posix.system.fchmodat(dir_fd, path, mode);
            switch (posix.errno(rc)) {
                .SUCCESS => return syscall.finish(),
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => |err| return errnoBug(err),
                        .ACCES => return error.AccessDenied,
                        .IO => return error.InputOutput,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NOENT => return error.FileNotFound,
                        .NOTDIR => return error.FileNotFound,
                        .NOMEM => return error.SystemResources,
                        .OPNOTSUPP => return error.OperationUnsupported,
                        .PERM => return error.PermissionDenied,
                        .ROFS => return error.ReadOnlyFileSystem,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (@atomicLoad(UseFchmodat2, &t.use_fchmodat2, .monotonic) == .disabled)
        return fchmodatFallback(dir_fd, path, mode);

    comptime assert(native_os == .linux);

    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.linux.errno(std.os.linux.fchmodat2(dir_fd, path, mode, flags))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .OPNOTSUPP => return error.OperationUnsupported,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .NOSYS => {
                        @atomicStore(UseFchmodat2, &t.use_fchmodat2, .disabled, .monotonic);
                        return fchmodatFallback(dir_fd, path, mode);
                    },
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fchmodatFallback(
    dir_fd: posix.fd_t,
    path: [*:0]const u8,
    mode: posix.mode_t,
) Dir.SetFilePermissionsError!void {
    comptime assert(native_os == .linux);

    // Fallback to changing permissions using procfs:
    //
    // 1. Open `path` as a `PATH` descriptor.
    // 2. Stat the fd and check if it isn't a symbolic link.
    // 3. Generate the procfs reference to the fd via `/proc/self/fd/{fd}`.
    // 4. Pass the procfs path to `chmod` with the `mode`.
    const path_fd: posix.fd_t = fd: {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = posix.system.openat(dir_fd, path, .{
                .PATH = true,
                .NOFOLLOW = true,
                .CLOEXEC = true,
            }, @as(posix.mode_t, 0));
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break :fd @intCast(rc);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => |err| return errnoBug(err),
                        .ACCES => return error.AccessDenied,
                        .PERM => return error.PermissionDenied,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NOENT => return error.FileNotFound,
                        .NOMEM => return error.SystemResources,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };
    defer closeFd(path_fd);

    const path_mode = mode: {
        const sys = if (statx_use_c) std.c else std.os.linux;
        const syscall: Syscall = try .start();
        while (true) {
            var statx = std.mem.zeroes(std.os.linux.Statx);
            switch (sys.errno(sys.statx(path_fd, "", posix.AT.EMPTY_PATH, .{ .TYPE = true }, &statx))) {
                .SUCCESS => {
                    syscall.finish();
                    if (!statx.mask.TYPE) return error.Unexpected;
                    break :mode statx.mode;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ACCES => return error.AccessDenied,
                        .LOOP => return error.SymLinkLoop,
                        .NOMEM => return error.SystemResources,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };

    // Even though we only wanted TYPE, the kernel can still fill in the additional bits.
    if ((path_mode & posix.S.IFMT) == posix.S.IFLNK)
        return error.OperationUnsupported;

    var procfs_buf: ["/proc/self/fd/-2147483648\x00".len]u8 = undefined;
    const proc_path = std.mem.printSentinel(&procfs_buf, "/proc/self/fd/{d}", .{path_fd}, 0) catch unreachable;
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.chmod(proc_path, mode))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .NOENT => return error.OperationUnsupported, // procfs not mounted.
                    .BADF => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirSetOwner = switch (native_os) {
    .windows => dirSetOwnerUnsupported,
    else => dirSetOwnerPosix,
};

fn dirSetOwnerUnsupported(userdata: ?*anyopaque, dir: Dir, owner: ?File.Uid, group: ?File.Gid) Dir.SetOwnerError!void {
    _ = userdata;
    _ = dir;
    _ = owner;
    _ = group;
    return error.Unexpected;
}

fn dirSetOwnerPosix(userdata: ?*anyopaque, dir: Dir, owner: ?File.Uid, group: ?File.Gid) Dir.SetOwnerError!void {
    if (!have_fchown) return error.Unexpected; // Unsupported OS, don't call this function.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const uid = owner orelse ~@as(posix.uid_t, 0);
    const gid = group orelse ~@as(posix.gid_t, 0);
    return posixFchown(dir.handle, uid, gid);
}

fn posixFchown(fd: posix.fd_t, uid: posix.uid_t, gid: posix.gid_t) File.SetOwnerError!void {
    comptime assert(have_fchown);
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.fchown(fd, uid, gid))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // likely fd refers to directory opened without `Dir.OpenOptions.iterate`
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirSetFileOwner(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    owner: ?File.Uid,
    group: ?File.Gid,
    options: Dir.SetFileOwnerOptions,
) Dir.SetFileOwnerError!void {
    if (!have_fchown) return error.Unexpected; // Unsupported OS, don't call this function.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    _ = dir;
    _ = sub_path_posix;
    _ = owner;
    _ = group;
    _ = options;
    @panic("TODO implement dirSetFileOwner");
}

const fileSync = switch (native_os) {
    .windows => windows_impl.fileSyncWindows,
    .wasi => wasi_impl.fileSyncWasi,
    else => fileSyncPosix,
};

fn fileSyncPosix(userdata: ?*anyopaque, file: File) File.SyncError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.fsync(file.handle))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ROFS => |err| return errnoBug(err),
                    .IO => return error.InputOutput,
                    .NOSPC => return error.NoSpaceLeft,
                    .DQUOT => return error.DiskQuota,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileIsTty(userdata: ?*anyopaque, file: File) Io.Cancelable!bool {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return isTty(file);
}

fn isTty(file: File) Io.Cancelable!bool {
    if (is_windows) {
        var get_console_mode = windows.CONSOLE.USER_IO.GET_MODE;
        switch ((try deviceIoControl(&.{
            .file = .{
                .handle = windows.peb().ProcessParameters.ConsoleHandle,
                .flags = .{ .nonblocking = false },
            },
            .code = windows.IOCTL.CONDRV.ISSUE_USER_IO,
            .in = @ptrCast(&get_console_mode.request(file, 0, .{}, 0, .{})),
        })).u.Status) {
            .SUCCESS => return true,
            .CANCELLED => unreachable,
            .INVALID_HANDLE => return isCygwinPty(file),
            else => return false,
        }
    }

    if (builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = posix.system.isatty(file.handle);
            switch (posix.errno(rc - 1)) {
                .SUCCESS => {
                    syscall.finish();
                    return true;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    return false;
                },
            }
        }
    }

    if (native_os == .wasi) {
        var statbuf: std.os.wasi.fdstat_t = undefined;
        const err = std.os.wasi.fd_fdstat_get(file.handle, &statbuf);
        if (err != .SUCCESS)
            return false;

        // A tty is a character device that we can't seek or tell on.
        if (statbuf.fs_filetype != .CHARACTER_DEVICE)
            return false;
        if (statbuf.fs_rights_base.FD_SEEK or statbuf.fs_rights_base.FD_TELL)
            return false;

        return true;
    }

    if (native_os == .linux) {
        const linux = std.os.linux;
        const syscall: Syscall = try .start();
        while (true) {
            var wsz: posix.winsize = undefined;
            const fd: usize = @bitCast(@as(isize, file.handle));
            const rc = linux.syscall3(.ioctl, fd, linux.T.IOCGWINSZ, @intFromPtr(&wsz));
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    return true;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    return false;
                },
            }
        }
    }

    @compileError("unimplemented");
}

fn fileEnableAnsiEscapeCodes(userdata: ?*anyopaque, file: File) File.EnableAnsiEscapeCodesError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    if (!is_windows) return if (!try supportsAnsiEscapeCodes(t, file)) error.NotTerminalDevice;

    // For Windows Terminal, VT Sequences processing is enabled by default.
    const console: File = .{
        .handle = windows.peb().ProcessParameters.ConsoleHandle,
        .flags = .{ .nonblocking = false },
    };
    var get_console_mode = windows.CONSOLE.USER_IO.GET_MODE;
    switch ((try deviceIoControl(&.{
        .file = console,
        .code = windows.IOCTL.CONDRV.ISSUE_USER_IO,
        .in = @ptrCast(&get_console_mode.request(file, 0, .{}, 0, .{})),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INVALID_HANDLE => return if (!try isCygwinPty(file)) error.NotTerminalDevice,
        else => return error.NotTerminalDevice,
    }

    if (get_console_mode.Data & windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0) return;

    // For Windows Console, VT Sequences processing support was added in Windows 10 build 14361, but disabled by default.
    // https://devblogs.microsoft.com/commandline/tmux-support-arrives-for-bash-on-ubuntu-on-windows/
    //
    // Note: In Microsoft's example for enabling virtual terminal processing, it
    // shows attempting to enable `DISABLE_NEWLINE_AUTO_RETURN` as well:
    // https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#example-of-enabling-virtual-terminal-processing
    // This is avoided because in the old Windows Console, that flag causes \n (as opposed to \r\n)
    // to behave unexpectedly (the cursor moves down 1 row but remains on the same column).
    // Additionally, the default console mode in Windows Terminal does not have
    // `DISABLE_NEWLINE_AUTO_RETURN` set, so by only enabling `ENABLE_VIRTUAL_TERMINAL_PROCESSING`
    // we end up matching the mode of Windows Terminal.
    var set_console_mode = windows.CONSOLE.USER_IO.SET_MODE(
        get_console_mode.Data | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    );
    switch ((try deviceIoControl(&.{
        .file = console,
        .code = windows.IOCTL.CONDRV.ISSUE_USER_IO,
        .in = @ptrCast(&set_console_mode.request(file, 0, .{}, 0, .{})),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        else => |status| return windows.unexpectedStatus(status),
    }
}

fn fileSupportsAnsiEscapeCodes(userdata: ?*anyopaque, file: File) Io.Cancelable!bool {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    return supportsAnsiEscapeCodes(t, file);
}

fn supportsAnsiEscapeCodes(t: *Threaded, file: File) Io.Cancelable!bool {
    if (is_windows) {
        var get_console_mode = windows.CONSOLE.USER_IO.GET_MODE;
        return switch ((try deviceIoControl(&.{
            .file = .{
                .handle = windows.peb().ProcessParameters.ConsoleHandle,
                .flags = .{ .nonblocking = false },
            },
            .code = windows.IOCTL.CONDRV.ISSUE_USER_IO,
            .in = @ptrCast(&get_console_mode.request(file, 0, .{}, 0, .{})),
        })).u.Status) {
            .SUCCESS => get_console_mode.Data & windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0,
            .CANCELLED => unreachable,
            .INVALID_HANDLE => isCygwinPty(file),
            else => false,
        };
    }

    if (native_os == .wasi) {
        // WASI sanitizes stdout when fd is a tty so ANSI escape codes
        // will not be interpreted as actual cursor commands, and
        // stderr is always sanitized.

        return false;
    }

    if (try isTty(file)) {
        if (file.handle == posix.STDOUT_FILENO or file.handle == posix.STDERR_FILENO) {
            t.scanEnviron();
            if (t.environ.string.TERM) |term| {
                if (std.mem.eql(u8, term, "dumb")) {
                    return false;
                }
            }
        }

        return true;
    }

    return false;
}

fn isCygwinPty(file: File) Io.Cancelable!bool {
    if (!is_windows) return false;

    const handle = file.handle;

    // If this is a MSYS2/cygwin pty, then it will be a named pipe with a name in one of these formats:
    //   msys-[...]-ptyN-[...]
    //   cygwin-[...]-ptyN-[...]
    //
    // Example: msys-1888ae32e00d56aa-pty0-to-master

    // First, just check that the handle is a named pipe.
    // This allows us to avoid the more costly NtQueryInformationFile call
    // for handles that aren't named pipes.
    {
        var io_status: windows.IO_STATUS_BLOCK = undefined;
        var device_info: windows.FILE.FS_DEVICE_INFORMATION = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtQueryVolumeInformationFile(
            handle,
            &io_status,
            &device_info,
            @sizeOf(windows.FILE.FS_DEVICE_INFORMATION),
            .Device,
        )) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => {
                syscall.finish();
                return false;
            },
        };
        if (device_info.DeviceType.FileDevice != .NAMED_PIPE) return false;
    }

    const name_bytes_offset = @offsetOf(windows.FILE.NAME_INFORMATION, "FileName");
    // `NAME_MAX` UTF-16 code units (2 bytes each)
    // This buffer may not be long enough to handle *all* possible paths
    // (PATH_MAX_WIDE would be necessary for that), but because we only care
    // about certain paths and we know they must be within a reasonable length,
    // we can use this smaller buffer and just return false on any error from
    // NtQueryInformationFile.
    const num_name_bytes = windows.MAX_PATH * 2;
    var name_info_bytes: [name_bytes_offset + num_name_bytes]u8 align(@alignOf(windows.FILE.NAME_INFORMATION)) = @splat(0);

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    const syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtQueryInformationFile(
        handle,
        &io_status_block,
        &name_info_bytes,
        @intCast(name_info_bytes.len),
        .Name,
    )) {
        .SUCCESS => break syscall.finish(),
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .INVALID_PARAMETER => unreachable,
        else => {
            syscall.finish();
            return false;
        },
    };

    const name_info: *const windows.FILE.NAME_INFORMATION = @ptrCast(&name_info_bytes);
    const name_bytes = name_info_bytes[name_bytes_offset .. name_bytes_offset + name_info.FileNameLength];
    const name_wide = std.mem.bytesAsSlice(u16, name_bytes);
    // The name we get from NtQueryInformationFile will be prefixed with a '\', e.g. \msys-1888ae32e00d56aa-pty0-to-master
    return (std.mem.startsWith(u16, name_wide, &[_]u16{ '\\', 'm', 's', 'y', 's', '-' }) or
        std.mem.startsWith(u16, name_wide, &[_]u16{ '\\', 'c', 'y', 'g', 'w', 'i', 'n', '-' })) and
        std.mem.find(u16, name_wide, &[_]u16{ '-', 'p', 't', 'y' }) != null;
}

fn fileSetLength(userdata: ?*anyopaque, file: File, length: u64) File.SetLengthError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const signed_len: i64 = @bitCast(length);
    if (signed_len < 0) return error.FileTooBig; // Avoid ambiguous EINVAL errors.

    if (is_windows) {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        var eof_info: windows.FILE.END_OF_FILE_INFORMATION = .{
            .EndOfFile = signed_len,
        };

        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtSetInformationFile(
            file.handle,
            &io_status_block,
            &eof_info,
            @sizeOf(windows.FILE.END_OF_FILE_INFORMATION),
            .EndOfFile,
        )) {
            .SUCCESS => return syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INVALID_HANDLE => |err| return syscall.ntstatusBug(err), // Handle not open for writing.
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
            .INVALID_PARAMETER => return syscall.fail(error.FileTooBig),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_filestat_set_size(file.handle, length)) {
                .SUCCESS => return syscall.finish(),
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FBIG => return error.FileTooBig,
                        .IO => return error.InputOutput,
                        .PERM => return error.PermissionDenied,
                        .TXTBSY => return error.FileBusy,
                        .BADF => |err| return errnoBug(err), // Handle not open for writing
                        .INVAL => return error.NonResizable,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(ftruncate_sym(file.handle, signed_len))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FBIG => return error.FileTooBig,
                    .IO => return error.InputOutput,
                    .PERM => return error.PermissionDenied,
                    .TXTBSY => return error.FileBusy,
                    .BADF => |err| return errnoBug(err), // Handle not open for writing.
                    .INVAL => return error.NonResizable, // This is returned for /dev/null for example.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileSetOwner(userdata: ?*anyopaque, file: File, owner: ?File.Uid, group: ?File.Gid) File.SetOwnerError!void {
    if (!have_fchown) return error.Unexpected; // Unsupported OS, don't call this function.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const uid = owner orelse ~@as(posix.uid_t, 0);
    const gid = group orelse ~@as(posix.gid_t, 0);
    return posixFchown(file.handle, uid, gid);
}

fn fileSetPermissions(userdata: ?*anyopaque, file: File, permissions: File.Permissions) File.SetPermissionsError!void {
    if (@sizeOf(File.Permissions) == 0) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    switch (native_os) {
        .windows => {
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            var info: windows.FILE.BASIC_INFORMATION = .{
                .CreationTime = 0,
                .LastAccessTime = 0,
                .LastWriteTime = 0,
                .ChangeTime = 0,
                .FileAttributes = permissions.toAttributes(),
            };
            const syscall: Syscall = try .start();
            while (true) switch (windows.ntdll.NtSetInformationFile(
                file.handle,
                &io_status_block,
                &info,
                @sizeOf(windows.FILE.BASIC_INFORMATION),
                .Basic,
            )) {
                .SUCCESS => return syscall.finish(),
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                .INVALID_HANDLE => |err| return syscall.ntstatusBug(err),
                .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
                else => |status| return syscall.unexpectedNtstatus(status),
            };
        },
        .wasi => return error.Unexpected, // Unsupported OS.
        else => return setPermissionsPosix(file.handle, permissions.toMode()),
    }
}

fn setPermissionsPosix(fd: posix.fd_t, mode: posix.mode_t) File.SetPermissionsError!void {
    comptime assert(have_fchmod);
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.fchmod(fd, mode))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirSetTimestamps(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.SetTimestampsOptions,
) Dir.SetTimestampsError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        @panic("TODO implement dirSetTimestamps windows");
    }

    if (native_os == .wasi and !builtin.link_libc) {
        @panic("TODO implement dirSetTimestamps wasi");
    }

    var times_buffer: [2]posix.timespec = undefined;
    const times = if (options.modify_timestamp == .now and options.access_timestamp == .now) null else p: {
        times_buffer = .{
            setTimestampToPosix(options.access_timestamp),
            setTimestampToPosix(options.modify_timestamp),
        };
        break :p &times_buffer;
    };

    const flags: u32 = if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.utimensat(dir.handle, sub_path_posix, times, flags))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .BADF => |err| return syscall.errnoBug(err), // always a race condition
        .FAULT => |err| return syscall.errnoBug(err),
        .INVAL => |err| return syscall.errnoBug(err),
        .ACCES => return syscall.fail(error.AccessDenied),
        .PERM => return syscall.fail(error.PermissionDenied),
        .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

fn fileSetTimestamps(
    userdata: ?*anyopaque,
    file: File,
    options: File.SetTimestampsOptions,
) File.SetTimestampsError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const now_sys = if (options.access_timestamp == .now or options.modify_timestamp == .now)
            windows.ntdll.RtlGetSystemTimePrecise()
        else
            undefined;
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.FILE.BASIC_INFORMATION = .{
            .CreationTime = 0,
            .LastAccessTime = switch (options.access_timestamp) {
                .unchanged => 0,
                .now => now_sys,
                .new => |ts| windows.toSysTime(ts),
            },
            .LastWriteTime = switch (options.modify_timestamp) {
                .unchanged => 0,
                .now => now_sys,
                .new => |ts| windows.toSysTime(ts),
            },
            .ChangeTime = 0,
            .FileAttributes = .{},
        };
        var syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtSetInformationFile(
            file.handle,
            &iosb,
            &info,
            @sizeOf(windows.FILE.BASIC_INFORMATION),
            .Basic,
        )) {
            .SUCCESS => return syscall.finish(),
            .CANCELLED => try syscall.checkCancel(),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    if (native_os == .wasi and !builtin.link_libc) {
        var atime: std.os.wasi.timestamp_t = 0;
        var mtime: std.os.wasi.timestamp_t = 0;
        var flags: std.os.wasi.fstflags_t = .{};

        switch (options.access_timestamp) {
            .unchanged => {},
            .now => flags.ATIM_NOW = true,
            .new => |ts| {
                atime = timestampToPosix(ts.nanoseconds).toTimestamp();
                flags.ATIM = true;
            },
        }

        switch (options.modify_timestamp) {
            .unchanged => {},
            .now => flags.MTIM_NOW = true,
            .new => |ts| {
                mtime = timestampToPosix(ts.nanoseconds).toTimestamp();
                flags.MTIM = true;
            },
        }

        const syscall: Syscall = try .start();
        while (true) switch (std.os.wasi.fd_filestat_set_times(file.handle, atime, mtime, flags)) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .BADF => |err| return syscall.errnoBug(err), // File descriptor use-after-free.
            .FAULT => |err| return syscall.errnoBug(err),
            .INVAL => |err| return syscall.errnoBug(err),
            .ACCES => return syscall.fail(error.AccessDenied),
            .PERM => return syscall.fail(error.PermissionDenied),
            .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
            else => |err| return syscall.unexpectedErrno(err),
        };
    }

    var times_buffer: [2]posix.timespec = undefined;
    const times = if (options.modify_timestamp == .now and options.access_timestamp == .now) null else p: {
        times_buffer = .{
            setTimestampToPosix(options.access_timestamp),
            setTimestampToPosix(options.modify_timestamp),
        };
        break :p &times_buffer;
    };

    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.futimens(file.handle, times))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .BADF => |err| return syscall.errnoBug(err), // always a race condition
        .FAULT => |err| return syscall.errnoBug(err),
        .INVAL => |err| return syscall.errnoBug(err),
        .ACCES => return syscall.fail(error.AccessDenied),
        .PERM => return syscall.fail(error.PermissionDenied),
        .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

pub const windows_lock_range_off: windows.LARGE_INTEGER = 0;
pub const windows_lock_range_len: windows.LARGE_INTEGER = 1;

fn fileLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!void {
    if (native_os == .wasi) return error.FileLocksUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const exclusive = switch (lock) {
            .none => {
                // To match the non-Windows behavior, unlock
                var io_status_block: windows.IO_STATUS_BLOCK = undefined;
                while (true) switch (windows.ntdll.NtUnlockFile(
                    file.handle,
                    &io_status_block,
                    &windows_lock_range_off,
                    &windows_lock_range_len,
                    0,
                )) {
                    .SUCCESS => return,
                    .CANCELLED => continue,
                    .RANGE_NOT_LOCKED => return,
                    .ACCESS_VIOLATION => |err| return windows.statusBug(err), // bad io_status_block pointer
                    else => |status| return windows.unexpectedStatus(status),
                };
            },
            .shared => false,
            .exclusive => true,
        };
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtLockFile(
            file.handle,
            null,
            null,
            null,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            null,
            .FALSE,
            .fromBool(exclusive),
        )) {
            .SUCCESS => return syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
            .LOCK_NOT_GRANTED => |err| return syscall.ntstatusBug(err), // passed FailImmediately=false
            .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    const operation: i32 = switch (lock) {
        .none => posix.LOCK.UN,
        .shared => posix.LOCK.SH,
        .exclusive => posix.LOCK.EX,
    };
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, operation))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOLCK => return error.SystemResources,
                    .AGAIN => |err| return errnoBug(err),
                    .OPNOTSUPP => return error.FileLocksUnsupported,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileTryLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!bool {
    if (native_os == .wasi) return error.FileLocksUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const exclusive = switch (lock) {
            .none => {
                // To match the non-Windows behavior, unlock
                var io_status_block: windows.IO_STATUS_BLOCK = undefined;
                while (true) switch (windows.ntdll.NtUnlockFile(
                    file.handle,
                    &io_status_block,
                    &windows_lock_range_off,
                    &windows_lock_range_len,
                    0,
                )) {
                    .SUCCESS => return true,
                    .CANCELLED => continue,
                    .RANGE_NOT_LOCKED => return false,
                    .ACCESS_VIOLATION => |err| return windows.statusBug(err), // bad io_status_block pointer
                    else => |status| return windows.unexpectedStatus(status),
                };
            },
            .shared => false,
            .exclusive => true,
        };
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtLockFile(
            file.handle,
            null,
            null,
            null,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            null,
            .TRUE,
            .fromBool(exclusive),
        )) {
            .SUCCESS => {
                syscall.finish();
                return true;
            },
            .LOCK_NOT_GRANTED => {
                syscall.finish();
                return false;
            },
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
            .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    const operation: i32 = switch (lock) {
        .none => posix.LOCK.UN,
        .shared => posix.LOCK.SH | posix.LOCK.NB,
        .exclusive => posix.LOCK.EX | posix.LOCK.NB,
    };
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, operation))) {
            .SUCCESS => {
                syscall.finish();
                return true;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .AGAIN => {
                syscall.finish();
                return false;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOLCK => return error.SystemResources,
                    .OPNOTSUPP => return error.FileLocksUnsupported,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileUnlock(userdata: ?*anyopaque, file: File) void {
    if (native_os == .wasi) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        while (true) switch (windows.ntdll.NtUnlockFile(
            file.handle,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            0,
        )) {
            .SUCCESS => return,
            .CANCELLED => continue,
            .RANGE_NOT_LOCKED => if (is_debug) unreachable else return, // Function asserts unlocked.
            .ACCESS_VIOLATION => if (is_debug) unreachable else return, // bad io_status_block pointer
            else => if (is_debug) unreachable else return, // Resource deallocation must succeed.
        };
    }

    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, posix.LOCK.UN))) {
            .SUCCESS => return,
            .CANCELED, .INTR => continue,
            .AGAIN => return assert(!is_debug), // unlocking can't block
            .BADF => return assert(!is_debug), // File descriptor used after closed.
            .INVAL => return assert(!is_debug), // invalid parameters
            .NOLCK => return assert(!is_debug), // Resource deallocation.
            .OPNOTSUPP => return assert(!is_debug), // We already got the lock.
            else => return assert(!is_debug), // Resource deallocation must succeed.
        }
    }
}

fn fileDowngradeLock(userdata: ?*anyopaque, file: File) File.DowngradeLockError!void {
    if (native_os == .wasi) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        // On Windows it works like a semaphore + exclusivity flag. To
        // implement this function, we first obtain another lock in shared
        // mode. This changes the exclusivity flag, but increments the
        // semaphore to 2. So we follow up with an NtUnlockFile which
        // decrements the semaphore but does not modify the exclusivity flag.
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtLockFile(
            file.handle,
            null,
            null,
            null,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            null,
            .TRUE,
            .FALSE,
        )) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INSUFFICIENT_RESOURCES => |err| return syscall.ntstatusBug(err),
            .LOCK_NOT_GRANTED => |err| return syscall.ntstatusBug(err), // File was not locked in exclusive mode.
            .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
            else => |status| return syscall.unexpectedNtstatus(status),
        };
        while (true) switch (windows.ntdll.NtUnlockFile(
            file.handle,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            0,
        )) {
            .SUCCESS => return,
            .CANCELLED => continue,
            .RANGE_NOT_LOCKED => if (is_debug) unreachable else return, // File was not locked.
            .ACCESS_VIOLATION => if (is_debug) unreachable else return, // bad io_status_block pointer
            else => if (is_debug) unreachable else return, // Resource deallocation must succeed.
        };
    }

    const operation = posix.LOCK.SH | posix.LOCK.NB;

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, operation))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .AGAIN => |err| return errnoBug(err), // File was not locked in exclusive mode.
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOLCK => |err| return errnoBug(err), // Lock already obtained.
                    .OPNOTSUPP => |err| return errnoBug(err), // Lock already obtained.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirHardLink(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
    options: Dir.HardLinkOptions,
) Dir.HardLinkError!void {
    if (is_windows) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (native_os == .wasi and !builtin.link_libc) {
        const flags: std.os.wasi.lookupflags_t = .{
            .SYMLINK_FOLLOW = options.follow_symlinks,
        };
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.path_link(
                old_dir.handle,
                flags,
                old_sub_path.ptr,
                old_sub_path.len,
                new_dir.handle,
                new_sub_path.ptr,
                new_sub_path.len,
            )) {
                .SUCCESS => return syscall.finish(),
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ACCES => return error.AccessDenied,
                        .DQUOT => return error.DiskQuota,
                        .EXIST => return error.PathAlreadyExists,
                        .FAULT => |err| return errnoBug(err),
                        .IO => return error.HardwareFailure,
                        .LOOP => return error.SymLinkLoop,
                        .MLINK => return error.LinkQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NOENT => return error.FileNotFound,
                        .NOMEM => return error.SystemResources,
                        .NOSPC => return error.NoSpaceLeft,
                        .NOTDIR => return error.NotDir,
                        .PERM => return error.PermissionDenied,
                        .ROFS => return error.ReadOnlyFileSystem,
                        .XDEV => return error.CrossDevice,
                        .INVAL => |err| return errnoBug(err),
                        .ILSEQ => return error.BadPathName,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    var old_path_buffer: [posix.PATH_MAX]u8 = undefined;
    var new_path_buffer: [posix.PATH_MAX]u8 = undefined;

    const old_sub_path_posix = try pathToPosix(old_sub_path, &old_path_buffer);
    const new_sub_path_posix = try pathToPosix(new_sub_path, &new_path_buffer);

    const flags: u32 = if (options.follow_symlinks) posix.AT.SYMLINK_FOLLOW else 0;
    return linkat(old_dir.handle, old_sub_path_posix, new_dir.handle, new_sub_path_posix, flags);
}

pub fn fileClose(userdata: ?*anyopaque, files: []const File) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    for (files) |file| {
        if (is_windows) {
            windows.CloseHandle(file.handle);
        } else {
            closeFd(file.handle);
        }
    }
}

fn fileReadStreaming(userdata: ?*anyopaque, file: File, data: []const []u8) File.ReadStreamingError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    if (is_windows) return windows_impl.fileReadStreamingWindows(file, data);
    return fileReadStreamingPosix(file, data);
}

fn fileReadStreamingPosix(file: File, data: []const []u8) File.ReadStreamingError!usize {
    var iovecs_buffer: [max_iovecs_len]posix.iovec = undefined;
    var i: usize = 0;
    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    if (i == 0) return 0;
    const dest = iovecs_buffer[0..i];
    assert(dest[0].len > 0);

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var nread: usize = undefined;
            switch (std.os.wasi.fd_read(file.handle, dest.ptr, dest.len, &nread)) {
                .SUCCESS => {
                    syscall.finish();
                    if (nread == 0) return error.EndOfStream;
                    return nread;
                },
                .INTR, .TIMEDOUT => {
                    try syscall.checkCancel();
                    continue;
                },
                .BADF => return syscall.fail(error.IsDir), // File operation on directory.
                .IO => return syscall.fail(error.InputOutput),
                .ISDIR => return syscall.fail(error.IsDir),
                .NOBUFS => return syscall.fail(error.SystemResources),
                .NOMEM => return syscall.fail(error.SystemResources),
                .NOTCONN => return syscall.fail(error.SocketUnconnected),
                .CONNRESET => return syscall.fail(error.ConnectionResetByPeer),
                .NOTCAPABLE => return syscall.fail(error.AccessDenied),
                .INVAL => |err| return syscall.errnoBug(err),
                .FAULT => |err| return syscall.errnoBug(err),
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.readv(file.handle, dest.ptr, @intCast(dest.len));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                if (rc == 0) return error.EndOfStream;
                return @intCast(rc);
            },
            .INTR, .TIMEDOUT => {
                try syscall.checkCancel();
                continue;
            },
            .BADF => {
                syscall.finish();
                if (native_os == .wasi) return error.IsDir; // File operation on directory.
                return error.NotOpenForReading;
            },
            .ACCES => return syscall.fail(error.AccessDenied),
            .AGAIN => return syscall.fail(error.WouldBlock),
            .IO => return syscall.fail(error.InputOutput),
            .ISDIR => return syscall.fail(error.IsDir),
            .NOBUFS => return syscall.fail(error.SystemResources),
            .NOMEM => return syscall.fail(error.SystemResources),
            .NOTCONN => return syscall.fail(error.SocketUnconnected),
            .CONNRESET => return syscall.fail(error.ConnectionResetByPeer),
            .INVAL => |err| return syscall.errnoBug(err),
            .FAULT => |err| return syscall.errnoBug(err),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

pub fn flagApc(userdata: ?*anyopaque, _: *windows.IO_STATUS_BLOCK, _: windows.ULONG) align(apc_align) callconv(.winapi) void {
    const flag: *bool = @ptrCast(userdata);
    flag.* = true;
}

fn fileReadPositionalPosix(file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
    var iovecs_buffer: [max_iovecs_len]posix.iovec = undefined;
    var i: usize = 0;
    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    if (i == 0) return 0;
    const dest = iovecs_buffer[0..i];
    assert(dest[0].len > 0);

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var nread: usize = undefined;
            switch (std.os.wasi.fd_pread(file.handle, dest.ptr, dest.len, offset, &nread)) {
                .SUCCESS => {
                    syscall.finish();
                    return nread;
                },
                .INTR, .TIMEDOUT => {
                    try syscall.checkCancel();
                    continue;
                },
                .NOTCONN => |err| return syscall.errnoBug(err), // not a socket
                .CONNRESET => |err| return syscall.errnoBug(err), // not a socket
                .INVAL => |err| return syscall.errnoBug(err),
                .FAULT => |err| return syscall.errnoBug(err), // segmentation fault
                .AGAIN => |err| return syscall.errnoBug(err),
                .IO => return syscall.fail(error.InputOutput),
                .ISDIR => return syscall.fail(error.IsDir),
                .BADF => return syscall.fail(error.IsDir),
                .NOBUFS => return syscall.fail(error.SystemResources),
                .NOMEM => return syscall.fail(error.SystemResources),
                .NXIO => return syscall.fail(error.Unseekable),
                .SPIPE => return syscall.fail(error.Unseekable),
                .OVERFLOW => return syscall.fail(error.Unseekable),
                .NOTCAPABLE => return syscall.fail(error.AccessDenied),
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    }

    if (have_preadv) {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = if (native_os == .haiku)
                posix.system.readv_pos(file.handle, @bitCast(offset), dest.ptr, @intCast(dest.len))
            else
                preadv_sym(file.handle, dest.ptr, @intCast(dest.len), @bitCast(offset));
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    return @bitCast(rc);
                },
                .INTR, .TIMEDOUT => {
                    try syscall.checkCancel();
                    continue;
                },
                .ACCES => return syscall.fail(error.AccessDenied),
                .NXIO => return syscall.fail(error.Unseekable),
                .SPIPE => return syscall.fail(error.Unseekable),
                .OVERFLOW => return syscall.fail(error.Unseekable),
                .NOBUFS => return syscall.fail(error.SystemResources),
                .NOMEM => return syscall.fail(error.SystemResources),
                .AGAIN => return syscall.fail(error.WouldBlock),
                .IO => return syscall.fail(error.InputOutput),
                .ISDIR => return syscall.fail(error.IsDir),
                .NOTCONN => |err| return syscall.errnoBug(err), // not a socket
                .CONNRESET => |err| return syscall.errnoBug(err), // not a socket
                .INVAL => |err| return syscall.errnoBug(err),
                .FAULT => |err| return syscall.errnoBug(err),
                .BADF => {
                    syscall.finish();
                    if (native_os == .wasi) return error.IsDir; // File operation on directory.
                    return error.NotOpenForReading;
                },
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = pread_sym(file.handle, dest[0].base, @intCast(dest[0].len), @bitCast(offset));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @bitCast(rc);
            },
            .INTR, .TIMEDOUT => {
                try syscall.checkCancel();
                continue;
            },
            .ACCES => return syscall.fail(error.AccessDenied),
            .NXIO => return syscall.fail(error.Unseekable),
            .SPIPE => return syscall.fail(error.Unseekable),
            .OVERFLOW => return syscall.fail(error.Unseekable),
            .NOBUFS => return syscall.fail(error.SystemResources),
            .NOMEM => return syscall.fail(error.SystemResources),
            .AGAIN => return syscall.fail(error.WouldBlock),
            .IO => return syscall.fail(error.InputOutput),
            .ISDIR => return syscall.fail(error.IsDir),
            .NOTCONN => |err| return syscall.errnoBug(err), // not a socket
            .CONNRESET => |err| return syscall.errnoBug(err), // not a socket
            .INVAL => |err| return syscall.errnoBug(err),
            .FAULT => |err| return syscall.errnoBug(err),
            .BADF => {
                syscall.finish();
                if (native_os == .wasi) return error.IsDir; // File operation on directory.
                return error.NotOpenForReading;
            },
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

fn fileReadPositional(userdata: ?*anyopaque, file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    if (is_windows) return windows_impl.fileReadPositionalWindows(file, data, offset);
    return fileReadPositionalPosix(file, data, offset);
}

fn fileSeekBy(userdata: ?*anyopaque, file: File, offset: i64) File.SeekError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.FILE.POSITION_INFORMATION = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtQueryInformationFile(
            file.handle,
            &iosb,
            &info,
            @sizeOf(windows.FILE.POSITION_INFORMATION),
            .Position,
        )) {
            .SUCCESS => break,
            .CANCELLED => try syscall.checkCancel(),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .PIPE_NOT_AVAILABLE => return syscall.fail(error.Unseekable),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
        info.CurrentByteOffset = @bitCast((if (offset >= 0) std.math.add(
            u64,
            @bitCast(info.CurrentByteOffset),
            @intCast(offset),
        ) else std.math.sub(
            u64,
            @bitCast(info.CurrentByteOffset),
            @intCast(-offset),
        )) catch |err| switch (err) {
            error.Overflow => return syscall.fail(error.Unseekable),
        });
        while (true) switch (windows.ntdll.NtSetInformationFile(
            file.handle,
            &iosb,
            &info,
            @sizeOf(windows.FILE.POSITION_INFORMATION),
            .Position,
        )) {
            .SUCCESS => return syscall.finish(),
            .CANCELLED => try syscall.checkCancel(),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .PIPE_NOT_AVAILABLE => return syscall.fail(error.Unseekable),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    if (native_os == .wasi and !builtin.link_libc) {
        var new_offset: std.os.wasi.filesize_t = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_seek(file.handle, offset, .CUR, &new_offset)) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (posix.SEEK == void) return error.Unseekable;

    if (native_os == .linux and !builtin.link_libc and @sizeOf(posix.system.syscall_arg_t) == 4) {
        var result: i64 = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.llseek(file.handle, offset, &result, posix.SEEK.CUR))) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(lseek_sym(file.handle, offset, posix.SEEK.CUR))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => return error.Unseekable,
                    .OVERFLOW => return error.Unseekable,
                    .SPIPE => return error.Unseekable,
                    .NXIO => return error.Unseekable,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileSeekTo(userdata: ?*anyopaque, file: File, offset: u64) File.SeekError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.FILE.POSITION_INFORMATION = .{ .CurrentByteOffset = @bitCast(offset) };
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtSetInformationFile(
            file.handle,
            &iosb,
            &info,
            @sizeOf(windows.FILE.POSITION_INFORMATION),
            .Position,
        )) {
            .SUCCESS => return syscall.finish(),
            .CANCELLED => try syscall.checkCancel(),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .PIPE_NOT_AVAILABLE => return syscall.fail(error.Unseekable),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var new_offset: std.os.wasi.filesize_t = undefined;
            switch (std.os.wasi.fd_seek(file.handle, @bitCast(offset), .SET, &new_offset)) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (posix.SEEK == void) return error.Unseekable;

    return posixSeekTo(file.handle, offset);
}

pub fn posixSeekTo(fd: posix.fd_t, offset: u64) File.SeekError!void {
    if (native_os == .linux and !builtin.link_libc and @sizeOf(posix.system.syscall_arg_t) == 4) {
        const syscall: Syscall = try .start();
        while (true) {
            var result: i64 = undefined;
            switch (posix.errno(posix.system.llseek(fd, @bitCast(offset), &result, posix.SEEK.SET))) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(lseek_sym(fd, @bitCast(offset), posix.SEEK.SET))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => return error.Unseekable,
                    .OVERFLOW => return error.Unseekable,
                    .SPIPE => return error.Unseekable,
                    .NXIO => return error.Unseekable,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn processExecutableOpen(userdata: ?*anyopaque, flags: Dir.OpenFileOptions) process.OpenExecutableError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    switch (native_os) {
        .wasi => return error.OperationUnsupported,
        .linux, .serenity => return dirOpenFilePosix(t, .{ .handle = posix.AT.FDCWD }, "/proc/self/exe", flags),
        .windows => {
            // If ImagePathName is a symlink, then it will contain the path of the symlink,
            // not the path that the symlink points to. However, because we are opening
            // the file, we can let the openFileW call follow the symlink for us.
            const image_path_name = windows.peb().ProcessParameters.ImagePathName.sliceZ();
            const prefixed_path_w = try windows_impl.wToPrefixedFileW(null, image_path_name, .{});
            return windows_impl.dirOpenFileWtf16(null, prefixed_path_w.span(), flags);
        },
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => {
            // _NSGetExecutablePath() returns a path that might be a symlink to
            // the executable. Here it does not matter since we open it.
            var symlink_path_buf: [posix.PATH_MAX + 1]u8 = undefined;
            var n: u32 = symlink_path_buf.len;
            const rc = std.c._NSGetExecutablePath(&symlink_path_buf, &n);
            if (rc != 0) return error.NameTooLong;
            const symlink_path = std.mem.sliceTo(&symlink_path_buf, 0);
            return dirOpenFilePosix(t, .cwd(), symlink_path, flags);
        },
        else => {
            var buffer: [Dir.max_path_bytes]u8 = undefined;
            const n = try processExecutablePath(t, &buffer);
            buffer[n] = 0;
            const executable_path = buffer[0..n :0];
            return dirOpenFilePosix(t, .cwd(), executable_path, flags);
        },
    }
}

fn processExecutablePath(userdata: ?*anyopaque, out_buffer: []u8) process.ExecutablePathError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    switch (native_os) {
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => {
            // _NSGetExecutablePath() returns a path that might be a symlink to
            // the executable.
            var symlink_path_buf: [posix.PATH_MAX + 1]u8 = undefined;
            var n: u32 = symlink_path_buf.len;
            const rc = std.c._NSGetExecutablePath(&symlink_path_buf, &n);
            if (rc != 0) return error.NameTooLong;
            const symlink_path = std.mem.sliceTo(&symlink_path_buf, 0);
            return Io.Dir.realPathFileAbsolute(io(t), symlink_path, out_buffer) catch |err| switch (err) {
                error.NetworkNotFound => unreachable, // Windows-only
                error.FileBusy => unreachable, // Windows-only
                else => |e| return e,
            };
        },
        .linux, .serenity => return Io.Dir.readLinkAbsolute(io(t), "/proc/self/exe", out_buffer) catch |err| switch (err) {
            error.UnsupportedReparsePointType => unreachable, // Windows-only
            error.NetworkNotFound => unreachable, // Windows-only
            error.FileBusy => unreachable, // Windows-only
            else => |e| return e,
        },
        .illumos => return Io.Dir.readLinkAbsolute(io(t), "/proc/self/path/a.out", out_buffer) catch |err| switch (err) {
            error.UnsupportedReparsePointType => unreachable, // Windows-only
            error.NetworkNotFound => unreachable, // Windows-only
            error.FileBusy => unreachable, // Windows-only
            else => |e| return e,
        },
        .freebsd, .dragonfly => {
            var mib: [4]c_int = .{ posix.CTL.KERN, posix.KERN.PROC, posix.KERN.PROC_PATHNAME, -1 };
            var out_len: usize = out_buffer.len;
            const syscall: Syscall = try .start();
            while (true) switch (posix.errno(posix.system.sysctl(&mib, mib.len, out_buffer.ptr, &out_len, null, 0))) {
                .SUCCESS => {
                    syscall.finish();
                    return out_len - 1; // discard terminating NUL
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                .PERM => return syscall.fail(error.PermissionDenied),
                .NOMEM => return syscall.fail(error.SystemResources),
                .FAULT => |err| return syscall.errnoBug(err),
                .NOENT => |err| return syscall.errnoBug(err),
                else => |err| return syscall.unexpectedErrno(err),
            };
        },
        .netbsd => {
            var mib = [4]c_int{ posix.CTL.KERN, posix.KERN.PROC_ARGS, -1, posix.KERN.PROC_PATHNAME };
            var out_len: usize = out_buffer.len;
            const syscall: Syscall = try .start();
            while (true) {
                switch (posix.errno(posix.system.sysctl(&mib, mib.len, out_buffer.ptr, &out_len, null, 0))) {
                    .SUCCESS => {
                        syscall.finish();
                        return out_len - 1; // discard terminating NUL
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    .PERM => return syscall.fail(error.PermissionDenied),
                    .NOMEM => return syscall.fail(error.SystemResources),
                    .FAULT => |err| return syscall.errnoBug(err),
                    .NOENT => |err| return syscall.errnoBug(err),
                    else => |err| return syscall.unexpectedErrno(err),
                }
            }
        },
        .openbsd, .haiku => {
            // The best we can do on these operating systems is check based on
            // the first process argument.
            const argv0 = std.mem.span(t.argv0.value orelse return error.OperationUnsupported);
            if (std.mem.findScalar(u8, argv0, '/') != null) {
                // argv[0] is a path (relative or absolute): use realpath(3) directly
                var resolved_buf: [std.c.PATH_MAX]u8 = undefined;
                const syscall: Syscall = try .start();
                while (true) {
                    if (std.c.realpath(argv0, &resolved_buf)) |p| {
                        assert(p == &resolved_buf);
                        break syscall.finish();
                    } else switch (@as(std.c.E, @fromBackingInt(@intCast(std.c._errno().*)))) {
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        else => |e| {
                            syscall.finish();
                            switch (e) {
                                .ACCES => return error.AccessDenied,
                                .INVAL => |err| return errnoBug(err), // the pathname argument is a null pointer
                                .IO => return error.InputOutput,
                                .LOOP => return error.SymLinkLoop,
                                .NAMETOOLONG => return error.NameTooLong,
                                .NOENT => return error.FileNotFound,
                                .NOTDIR => return error.NotDir,
                                .NOMEM => |err| return errnoBug(err), // sufficient storage space is unavailable for allocation
                                else => |err| return posix.unexpectedErrno(err),
                            }
                        },
                    }
                }
                const resolved = std.mem.sliceTo(&resolved_buf, 0);
                if (resolved.len > out_buffer.len)
                    return error.NameTooLong;
                @memcpy(out_buffer[0..resolved.len], resolved);
                return resolved.len;
            } else if (argv0.len != 0) {
                // argv[0] is not empty (and not a path): search PATH
                t.scanEnviron();
                const PATH = t.environ.string.PATH orelse return error.FileNotFound;
                var it = std.mem.tokenizeScalar(u8, PATH, ':');
                it: while (it.next()) |dir| {
                    var resolved_path_buf: [std.c.PATH_MAX]u8 = undefined;
                    const resolved_path = std.mem.printSentinel(&resolved_path_buf, "{s}/{s}", .{
                        dir, argv0,
                    }, 0) catch continue;

                    var resolved_buf: [std.c.PATH_MAX]u8 = undefined;
                    const syscall: Syscall = try .start();
                    while (true) {
                        if (std.c.realpath(resolved_path, &resolved_buf)) |p| {
                            assert(p == &resolved_buf);
                            break syscall.finish();
                        } else switch (@as(std.c.E, @fromBackingInt(@intCast(std.c._errno().*)))) {
                            .INTR => {
                                try syscall.checkCancel();
                                continue;
                            },
                            .NAMETOOLONG => {
                                syscall.finish();
                                return error.NameTooLong;
                            },
                            .NOMEM => {
                                syscall.finish();
                                return error.SystemResources;
                            },
                            .IO => {
                                syscall.finish();
                                return error.InputOutput;
                            },
                            .ACCES, .LOOP, .NOENT, .NOTDIR => {
                                syscall.finish();
                                continue :it;
                            },
                            else => |err| {
                                syscall.finish();
                                return posix.unexpectedErrno(err);
                            },
                        }
                    }
                    const resolved = std.mem.sliceTo(&resolved_buf, 0);
                    if (resolved.len > out_buffer.len)
                        return error.NameTooLong;
                    @memcpy(out_buffer[0..resolved.len], resolved);
                    return resolved.len;
                }
            }
            return error.FileNotFound;
        },
        .windows => {
            // If ImagePathName is a symlink, then it will contain the path of the
            // symlink, not the path that the symlink points to. We want the path
            // that the symlink points to, though, so we need to get the realpath.
            var path_name_w_buf = try windows_impl.wToPrefixedFileW(
                null,
                windows.peb().ProcessParameters.ImagePathName.sliceZ(),
                .{},
            );

            const h_file = handle: {
                if (OpenFile(path_name_w_buf.span(), .{
                    .dir = null,
                    .access_mask = .{
                        .GENERIC = .{ .READ = true },
                        .STANDARD = .{ .SYNCHRONIZE = true },
                    },
                    .creation = .OPEN,
                    .filter = .any,
                })) |handle| {
                    break :handle handle;
                } else |err| switch (err) {
                    error.WouldBlock => unreachable,
                    error.FileBusy => unreachable,
                    else => |e| return e,
                }
            };
            defer windows.CloseHandle(h_file);

            const wide_slice = try windows_impl.GetFinalPathNameByHandle(h_file, .{}, &path_name_w_buf.data);

            const len = std.unicode.calcWtf8Len(wide_slice);
            if (len > out_buffer.len)
                return error.NameTooLong;

            const end_index = std.unicode.wtf16LeToWtf8(out_buffer, wide_slice);
            return end_index;
        },
        else => return error.OperationUnsupported,
    }
}

fn fileWritePositional(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
    offset: u64,
) File.WritePositionalError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        if (header.len != 0) {
            return windows_impl.writeFilePositionalWindows(file, header, offset);
        }
        for (data[0 .. data.len - 1]) |buf| {
            if (buf.len == 0) continue;
            return windows_impl.writeFilePositionalWindows(file, buf, offset);
        }
        const pattern = data[data.len - 1];
        if (pattern.len == 0 or splat == 0) return 0;
        return windows_impl.writeFilePositionalWindows(file, pattern, offset);
    }

    var iovecs: [max_iovecs_len]posix.iovec_const = undefined;
    var iovlen: iovlen_t = 0;
    addBuf(&iovecs, &iovlen, header);
    for (data[0 .. data.len - 1]) |bytes| addBuf(&iovecs, &iovlen, bytes);
    const pattern = data[data.len - 1];

    var splat_backup_buffer: [splat_buffer_size]u8 = undefined;
    if (iovecs.len - iovlen != 0) switch (splat) {
        0 => {},
        1 => addBuf(&iovecs, &iovlen, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                const splat_buffer = &splat_backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addBuf(&iovecs, &iovlen, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - iovlen != 0) {
                    assert(buf.len == splat_buffer.len);
                    addBuf(&iovecs, &iovlen, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addBuf(&iovecs, &iovlen, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - iovlen)) |_| {
                addBuf(&iovecs, &iovlen, pattern);
            },
        },
    };

    if (iovlen == 0) return 0;

    if (native_os == .wasi and !builtin.link_libc) {
        var n_written: usize = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_pwrite(file.handle, &iovecs, iovlen, offset, &n_written)) {
                .SUCCESS => {
                    syscall.finish();
                    return n_written;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .AGAIN => |err| return errnoBug(err),
                        .BADF => return error.NotOpenForWriting,
                        .DESTADDRREQ => |err| return errnoBug(err), // `connect` was never called.
                        .DQUOT => return error.DiskQuota,
                        .FBIG => return error.FileTooBig,
                        .IO => return error.InputOutput,
                        .NOSPC => return error.NoSpaceLeft,
                        .PERM => return error.PermissionDenied,
                        .PIPE => return error.BrokenPipe,
                        .NOTCAPABLE => return error.AccessDenied,
                        .NXIO => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = if (native_os == .haiku)
            posix.system.writev_pos(file.handle, @bitCast(offset), &iovecs, @intCast(iovlen))
        else
            pwritev_sym(file.handle, &iovecs, @intCast(iovlen), @bitCast(offset));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .INVAL => |err| return syscall.errnoBug(err),
            .FAULT => |err| return syscall.errnoBug(err),
            .DESTADDRREQ => |err| return syscall.errnoBug(err), // `connect` was never called.
            .CONNRESET => |err| return syscall.errnoBug(err), // Not a socket handle.
            .BADF => return syscall.fail(error.NotOpenForWriting),
            .AGAIN => return syscall.fail(error.WouldBlock),
            .DQUOT => return syscall.fail(error.DiskQuota),
            .FBIG => return syscall.fail(error.FileTooBig),
            .IO => return syscall.fail(error.InputOutput),
            .NOSPC => return syscall.fail(error.NoSpaceLeft),
            .PERM => return syscall.fail(error.PermissionDenied),
            .PIPE => return syscall.fail(error.BrokenPipe),
            .BUSY => return syscall.fail(error.DeviceBusy),
            .TXTBSY => return syscall.fail(error.FileBusy),
            .NXIO => return syscall.fail(error.Unseekable),
            .SPIPE => return syscall.fail(error.Unseekable),
            .OVERFLOW => return syscall.fail(error.Unseekable),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

fn fileWriteStreaming(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
) File.Writer.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const buffer = windows_impl.windowsWriteBuffer(header, data, splat);
        if (buffer.len == 0) return 0;
        return windows_impl.fileWriteStreamingWindows(file, buffer);
    }

    var iovecs: [max_iovecs_len]posix.iovec_const = undefined;
    var iovlen: iovlen_t = 0;
    addBuf(&iovecs, &iovlen, header);
    for (data[0 .. data.len - 1]) |bytes| addBuf(&iovecs, &iovlen, bytes);
    const pattern = data[data.len - 1];

    var splat_backup_buffer: [splat_buffer_size]u8 = undefined;
    if (iovecs.len - iovlen != 0) switch (splat) {
        0 => {},
        1 => addBuf(&iovecs, &iovlen, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                const splat_buffer = &splat_backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addBuf(&iovecs, &iovlen, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - iovlen != 0) {
                    assert(buf.len == splat_buffer.len);
                    addBuf(&iovecs, &iovlen, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addBuf(&iovecs, &iovlen, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - iovlen)) |_| {
                addBuf(&iovecs, &iovlen, pattern);
            },
        },
    };

    if (iovlen == 0) return 0;

    if (native_os == .wasi and !builtin.link_libc) {
        var n_written: usize = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_write(file.handle, &iovecs, iovlen, &n_written)) {
                .SUCCESS => {
                    syscall.finish();
                    return n_written;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .AGAIN => |err| return errnoBug(err),
                        .BADF => return error.NotOpenForWriting, // can be a race condition.
                        .DESTADDRREQ => |err| return errnoBug(err), // `connect` was never called.
                        .DQUOT => return error.DiskQuota,
                        .FBIG => return error.FileTooBig,
                        .IO => return error.InputOutput,
                        .NOSPC => return error.NoSpaceLeft,
                        .PERM => return error.PermissionDenied,
                        .PIPE => return error.BrokenPipe,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.writev(file.handle, &iovecs, @intCast(iovlen));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .AGAIN => return error.WouldBlock,
                    .BADF => return error.NotOpenForWriting, // Can be a race condition.
                    .DESTADDRREQ => |err| return errnoBug(err), // `connect` was never called.
                    .DQUOT => return error.DiskQuota,
                    .FBIG => return error.FileTooBig,
                    .IO => return error.InputOutput,
                    .NOSPC => return error.NoSpaceLeft,
                    .PERM => return error.PermissionDenied,
                    .PIPE => return error.BrokenPipe,
                    .CONNRESET => |err| return errnoBug(err), // Not a socket handle.
                    .BUSY => return error.DeviceBusy,
                    .ACCES => return error.AccessDenied,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileWriteFileStreaming(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    file_reader: *File.Reader,
    limit: Io.Limit,
) File.Writer.WriteFileError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const reader_buffered = file_reader.interface.buffered();
    if (reader_buffered.len >= @backingInt(limit)) {
        const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
        file_reader.interface.toss(n -| header.len);
        return n;
    }
    const file_limit = @backingInt(limit) - reader_buffered.len;
    const out_fd = file.handle;
    const in_fd = file_reader.file.handle;

    if (file_reader.size) |size| {
        if (size - file_reader.pos == 0) {
            if (reader_buffered.len != 0) {
                const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
                file_reader.interface.toss(n -| header.len);
                return n;
            } else {
                return error.EndOfStream;
            }
        }
    }

    if (native_os == .freebsd) sf: {
        // Try using sendfile on FreeBSD.
        if (@atomicLoad(UseSendfile, &t.use_sendfile, .monotonic) == .disabled) break :sf;
        const offset = std.math.cast(std.c.off_t, file_reader.pos) orelse break :sf;
        var hdtr_data: std.c.sf_hdtr = undefined;
        var headers: [2]posix.iovec_const = undefined;
        var headers_i: u8 = 0;
        if (header.len != 0) {
            headers[headers_i] = .{ .base = header.ptr, .len = header.len };
            headers_i += 1;
        }
        if (reader_buffered.len != 0) {
            headers[headers_i] = .{ .base = reader_buffered.ptr, .len = reader_buffered.len };
            headers_i += 1;
        }
        const hdtr: ?*std.c.sf_hdtr = if (headers_i == 0) null else b: {
            hdtr_data = .{
                .headers = &headers,
                .hdr_cnt = headers_i,
                .trailers = null,
                .trl_cnt = 0,
            };
            break :b &hdtr_data;
        };
        var sbytes: std.c.off_t = 0;
        const nbytes: usize = @min(file_limit, std.math.maxInt(usize));
        const flags = 0;

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(std.c.sendfile(in_fd, out_fd, offset, nbytes, hdtr, &sbytes, flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INVAL, .OPNOTSUPP, .NOTSOCK, .NOSYS => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
                .INTR, .BUSY => {
                    if (sbytes == 0) {
                        try syscall.checkCancel();
                        continue;
                    } else {
                        // Even if we are being canceled, there have been side
                        // effects, so it is better to report those side
                        // effects to the caller.
                        syscall.finish();
                        break;
                    }
                },
                .AGAIN => {
                    syscall.finish();
                    if (sbytes == 0) return error.WouldBlock;
                    break;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOTCONN => return error.BrokenPipe,
                        .IO => return error.InputOutput,
                        .PIPE => return error.BrokenPipe,
                        .NOBUFS => return error.SystemResources,
                        .BADF => |err| errnoBug(err),
                        .FAULT => |err| errnoBug(err),
                        else => |err| posix.unexpectedErrno(err),
                    });
                    // Give calling code chance to observe the error before trying
                    // something else.
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
            }
        }
        if (sbytes == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        const ubytes: usize = @intCast(sbytes);
        file_reader.interface.toss(ubytes -| header.len);
        return ubytes;
    }

    if (is_darwin) sf: {
        // Try using sendfile on macOS.
        if (@atomicLoad(UseSendfile, &t.use_sendfile, .monotonic) == .disabled) break :sf;
        const offset = std.math.cast(std.c.off_t, file_reader.pos) orelse break :sf;
        var hdtr_data: std.c.sf_hdtr = undefined;
        var headers: [2]posix.iovec_const = undefined;
        var headers_i: u8 = 0;
        if (header.len != 0) {
            headers[headers_i] = .{ .base = header.ptr, .len = header.len };
            headers_i += 1;
        }
        if (reader_buffered.len != 0) {
            headers[headers_i] = .{ .base = reader_buffered.ptr, .len = reader_buffered.len };
            headers_i += 1;
        }
        const hdtr: ?*std.c.sf_hdtr = if (headers_i == 0) null else b: {
            hdtr_data = .{
                .headers = &headers,
                .hdr_cnt = headers_i,
                .trailers = null,
                .trl_cnt = 0,
            };
            break :b &hdtr_data;
        };
        const max_count = std.math.maxInt(i32); // Avoid EINVAL.
        var len: std.c.off_t = @min(file_limit, max_count);
        const flags = 0;
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(std.c.sendfile(in_fd, out_fd, offset, &len, hdtr, flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .OPNOTSUPP, .NOTSOCK, .NOSYS => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
                .INTR => {
                    if (len == 0) {
                        try syscall.checkCancel();
                        continue;
                    } else {
                        // Even if we are being canceled, there have been side
                        // effects, so it is better to report those side
                        // effects to the caller.
                        syscall.finish();
                        break;
                    }
                },
                .AGAIN => {
                    syscall.finish();
                    if (len == 0) return error.WouldBlock;
                    break;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOTCONN => return error.BrokenPipe,
                        .IO => return error.InputOutput,
                        .PIPE => return error.BrokenPipe,
                        .BADF => |err| errnoBug(err),
                        .FAULT => |err| errnoBug(err),
                        .INVAL => |err| errnoBug(err),
                        else => |err| posix.unexpectedErrno(err),
                    });
                    // Give calling code chance to observe the error before trying
                    // something else.
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
            }
        }
        if (len == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        const u_len: usize = @bitCast(len);
        file_reader.interface.toss(u_len -| header.len);
        return u_len;
    }

    if (native_os == .linux) sf: {
        // Try using sendfile on Linux.
        if (@atomicLoad(UseSendfile, &t.use_sendfile, .monotonic) == .disabled) break :sf;
        // Linux sendfile does not support headers.
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        const max_count = 0x7ffff000; // Avoid EINVAL.
        var off: std.os.linux.off_t = undefined;
        const off_ptr: ?*std.os.linux.off_t, const count: usize = switch (file_reader.mode) {
            .positional => o: {
                const size = file_reader.getSize() catch |err| switch (err) {
                    error.Canceled => |e| return e,
                    else => break :sf,
                };
                off = std.math.cast(std.os.linux.off_t, file_reader.pos) orelse return error.ReadFailed;
                break :o .{ &off, @min(@backingInt(limit), size - file_reader.pos, max_count) };
            },
            .streaming => .{ null, limit.minInt(max_count) },
            .streaming_simple, .positional_simple => break :sf,
            .failure => return error.ReadFailed,
        };
        const syscall: Syscall = try .start();
        const n: usize = while (true) {
            const rc = sendfile_sym(out_fd, in_fd, off_ptr, count);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break @intCast(rc);
                },
                .NOSYS, .INVAL => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOTCONN => return error.BrokenPipe, // `out_fd` is an unconnected socket
                        .AGAIN => return error.WouldBlock,
                        .IO => return error.InputOutput,
                        .PIPE => return error.BrokenPipe,
                        .NOMEM => return error.SystemResources,
                        .NXIO, .SPIPE => {
                            file_reader.mode = file_reader.mode.toStreaming();
                            const pos = file_reader.pos;
                            if (pos != 0) {
                                file_reader.pos = 0;
                                file_reader.seekBy(@intCast(pos)) catch {
                                    file_reader.mode = .failure;
                                    return error.ReadFailed;
                                };
                            }
                            return 0;
                        },
                        .BADF => |err| errnoBug(err), // Always a race condition.
                        .FAULT => |err| errnoBug(err), // Segmentation fault.
                        .OVERFLOW => |err| errnoBug(err), // We avoid passing too large of a `count`.
                        else => |err| posix.unexpectedErrno(err),
                    });
                    // Give calling code chance to observe the error before trying
                    // something else.
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
            }
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        return n;
    }

    if (have_copy_file_range) cfr: {
        if (@atomicLoad(UseCopyFileRange, &t.use_copy_file_range, .monotonic) == .disabled) break :cfr;
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        var len: usize = @backingInt(limit);
        var off_in: i64 = undefined;
        const off_in_ptr: ?*i64 = switch (file_reader.mode) {
            .positional_simple, .streaming_simple => return error.Unimplemented,
            .positional => p: {
                len = @min(len, std.math.maxInt(usize) - file_reader.pos);
                off_in = @intCast(file_reader.pos);
                break :p &off_in;
            },
            .streaming => null,
            .failure => return error.ReadFailed,
        };
        const n: usize = switch (native_os) {
            .linux => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = linux_copy_file_range_sys.copy_file_range(in_fd, off_in_ptr, out_fd, null, len, 0);
                    switch (linux_copy_file_range_sys.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .NOMEM => return error.SystemResources,
                                .NOSPC => return error.NoSpaceLeft,
                                .OVERFLOW => |err| errnoBug(err), // We avoid passing too large a count.
                                .PERM => return error.PermissionDenied,
                                .BUSY => return error.DeviceBusy,
                                .TXTBSY => return error.FileBusy,
                                // copy_file_range can still work but not on
                                // this pair of file descriptors.
                                .XDEV => return error.Unimplemented,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            .freebsd => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = std.c.copy_file_range(in_fd, off_in_ptr, out_fd, null, @backingInt(limit), 0);
                    switch (std.c.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .INTEGRITY => return error.CorruptedData,
                                .NOSPC => return error.NoSpaceLeft,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            else => comptime unreachable,
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        return n;
    }

    return error.Unimplemented;
}

fn fileWriteFilePositional(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    file_reader: *File.Reader,
    limit: Io.Limit,
    offset: u64,
) File.WriteFilePositionalError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const reader_buffered = file_reader.interface.buffered();
    if (reader_buffered.len >= @backingInt(limit)) {
        const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
        file_reader.interface.toss(n -| header.len);
        return n;
    }
    const out_fd = file.handle;
    const in_fd = file_reader.file.handle;

    if (file_reader.size) |size| {
        if (size - file_reader.pos == 0) {
            if (reader_buffered.len != 0) {
                const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
                file_reader.interface.toss(n -| header.len);
                return n;
            } else {
                return error.EndOfStream;
            }
        }
    }

    if (have_copy_file_range) cfr: {
        if (@atomicLoad(UseCopyFileRange, &t.use_copy_file_range, .monotonic) == .disabled) break :cfr;
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        var len: usize = @min(@backingInt(limit), std.math.maxInt(usize) - offset);
        var off_in: i64 = undefined;
        const off_in_ptr: ?*i64 = switch (file_reader.mode) {
            .positional_simple, .streaming_simple => return error.Unimplemented,
            .positional => p: {
                len = @min(len, std.math.maxInt(usize) - file_reader.pos);
                off_in = @intCast(file_reader.pos);
                break :p &off_in;
            },
            .streaming => null,
            .failure => return error.ReadFailed,
        };
        var off_out: i64 = @intCast(offset);
        const n: usize = switch (native_os) {
            .linux => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = linux_copy_file_range_sys.copy_file_range(in_fd, off_in_ptr, out_fd, &off_out, len, 0);
                    switch (linux_copy_file_range_sys.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .NOMEM => return error.SystemResources,
                                .NOSPC => return error.NoSpaceLeft,
                                .OVERFLOW => |err| errnoBug(err), // We avoid passing too large a count.
                                .NXIO => return error.Unseekable,
                                .SPIPE => return error.Unseekable,
                                .PERM => return error.PermissionDenied,
                                .TXTBSY => return error.FileBusy,
                                // copy_file_range can still work but not on
                                // this pair of file descriptors.
                                .XDEV => return error.Unimplemented,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            .freebsd => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = std.c.copy_file_range(in_fd, off_in_ptr, out_fd, &off_out, @backingInt(limit), 0);
                    switch (std.c.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .INTEGRITY => return error.CorruptedData,
                                .NOSPC => return error.NoSpaceLeft,
                                .OVERFLOW => return error.Unseekable,
                                .NXIO => return error.Unseekable,
                                .SPIPE => return error.Unseekable,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            else => comptime unreachable,
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        return n;
    }

    if (is_darwin) fcf: {
        if (@atomicLoad(UseFcopyfile, &t.use_fcopyfile, .monotonic) == .disabled) break :fcf;
        if (file_reader.pos != 0) break :fcf;
        if (offset != 0) break :fcf;
        if (limit != .unlimited) break :fcf;
        const size = file_reader.getSize() catch |err| switch (err) {
            error.Canceled => |e| return e,
            else => break :fcf,
        };
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        const syscall: Syscall = try .start();
        while (true) {
            const rc = std.c.fcopyfile(in_fd, out_fd, null, .{ .DATA = true });
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                .OPNOTSUPP => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseFcopyfile, &t.use_fcopyfile, .disabled, .monotonic);
                    return 0;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOMEM => return error.SystemResources,
                        .INVAL => |err| errnoBug(err),
                        else => |err| posix.unexpectedErrno(err),
                    });
                    return 0;
                },
            }
        }
        file_reader.pos = size;
        return size;
    }

    return error.Unimplemented;
}

fn nowPosix(clock: Io.Clock) Io.Timestamp {
    const clock_id: posix.clockid_t = clockToPosix(clock);
    var timespec: posix.timespec = undefined;
    switch (posix.errno(posix.system.clock_gettime(clock_id, &timespec))) {
        .SUCCESS => return timestampFromPosix(&timespec),
        else => return .zero,
    }
}

fn now(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return switch (native_os) {
        .windows => windows_impl.nowWindows(clock),
        .wasi => wasi_impl.nowWasi(clock),
        else => nowPosix(clock),
    };
}

fn clockResolution(userdata: ?*anyopaque, clock: Io.Clock) Io.Clock.ResolutionError!Io.Duration {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return switch (native_os) {
        .windows => switch (clock) {
            .awake, .boot, .real => {
                // We don't need to cache QPF as it's internally just a memory read to KUSER_SHARED_DATA
                // (a read-only page of info updated and mapped by the kernel to all processes):
                // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
                // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
                var qpf: windows.LARGE_INTEGER = undefined;
                if (!windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) {
                    recoverableOsBugDetected();
                    return .zero;
                }
                // 10Mhz (1 qpc tick every 100ns) is a common enough QPF value that we can optimize on it.
                // https://github.com/microsoft/STL/blob/785143a0c73f030238ef618890fd4d6ae2b3a3a0/stl/inc/chrono#L694-L701
                const common_qpf = 10_000_000;
                if (qpf == common_qpf) return .fromNanoseconds(std.time.ns_per_s / common_qpf);

                // Convert to ns using fixed point.
                const scale = @as(u64, std.time.ns_per_s << 32) / @as(u32, @intCast(qpf));
                const result = scale >> 32;
                return .fromNanoseconds(result);
            },
            .cpu_process, .cpu_thread => return error.ClockUnavailable,
        },
        .wasi => {
            if (builtin.link_libc) return clockResolutionPosix(clock);
            var ns: std.os.wasi.timestamp_t = undefined;
            return switch (std.os.wasi.clock_res_get(wasi_impl.clockToWasi(clock), &ns)) {
                .SUCCESS => .fromNanoseconds(ns),
                .INVAL => return error.ClockUnavailable,
                else => |err| return posix.unexpectedErrno(err),
            };
        },
        else => return clockResolutionPosix(clock),
    };
}

fn clockResolutionPosix(clock: Io.Clock) Io.Clock.ResolutionError!Io.Duration {
    const clock_id: posix.clockid_t = clockToPosix(clock);
    var timespec: posix.timespec = undefined;
    return switch (posix.errno(posix.system.clock_getres(clock_id, &timespec))) {
        .SUCCESS => .fromNanoseconds(nanosecondsFromPosix(&timespec)),
        .INVAL => return error.ClockUnavailable,
        else => |err| return posix.unexpectedErrno(err),
    };
}

fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (use_parking_sleep) return parking_sleep.sleep(timeout);
    if (native_os == .wasi) return wasi_impl.sleepWasi(t, timeout);
    if (@TypeOf(posix.system.clock_nanosleep) != void) return sleepPosix(timeout);
    return sleepNanosleep(t, timeout);
}

fn sleepPosix(timeout: Io.Timeout) Io.Cancelable!void {
    const clock_id: posix.clockid_t = clockToPosix(switch (timeout) {
        .none => .awake,
        .duration => |d| d.clock,
        .deadline => |d| d.clock,
    });
    const deadline_nanoseconds: i96 = switch (timeout) {
        .none => std.math.maxInt(i96),
        .duration => |duration| duration.raw.nanoseconds,
        .deadline => |deadline| deadline.raw.nanoseconds,
    };
    var timespec: posix.timespec = timestampToPosix(deadline_nanoseconds);
    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.clock_nanosleep(clock_id, .{ .ABSTIME = switch (timeout) {
            .none, .duration => false,
            .deadline => true,
        } }, &timespec, &timespec);
        // POSIX-standard libc clock_nanosleep() returns *positive* errno values directly
        switch (if (builtin.link_libc) @as(posix.E, @fromBackingInt(@intCast(rc))) else posix.errno(rc)) {
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            // Handles SUCCESS as well as clock not available and unexpected
            // errors. The user had a chance to check clock resolution before
            // getting here, which would have reported 0, making this a legal
            // amount of time to sleep.
            else => {
                syscall.finish();
                return;
            },
        }
    }
}

fn sleepNanosleep(t: *Threaded, timeout: Io.Timeout) Io.Cancelable!void {
    const t_io = io(t);
    const sec_type = @typeInfo(posix.timespec).@"struct".field_types[0];
    const nsec_type = @typeInfo(posix.timespec).@"struct".field_types[1];

    var timespec: posix.timespec = t: {
        const d = timeout.toDurationFromNow(t_io) orelse break :t .{
            .sec = std.math.maxInt(sec_type),
            .nsec = std.math.maxInt(nsec_type),
        };
        break :t timestampToPosix(d.raw.toNanoseconds());
    };
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.nanosleep(&timespec, &timespec))) {
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            // This prong handles success as well as unexpected errors.
            else => return syscall.finish(),
        }
    }
}

pub fn setCloexec(fd: posix.fd_t) error{ Canceled, Unexpected }!void {
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC)))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        else => |err| return syscall.unexpectedErrno(err),
    };
}

/// This is either usize or u32. Since, either is fine, let's use the same
/// `addBuf` function for both writing to a file and sending network messages.
const iovlen_t = switch (native_os) {
    .wasi => u32,
    else => @FieldType(posix.msghdr_const, "iovlen"),
};

pub fn addBuf(v: []posix.iovec_const, i: *iovlen_t, bytes: []const u8) void {
    // OS checks ptr addr before length so zero length vectors must be omitted.
    if (bytes.len == 0) return;
    if (v.len - i.* == 0) return;
    v[i.*] = .{ .base = bytes.ptr, .len = bytes.len };
    i.* += 1;
}

fn lockStderr(userdata: ?*anyopaque, terminal_mode: ?Io.Terminal.Mode) Io.Cancelable!Io.LockedStderr {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const current_thread_id = Thread.currentId();

    if (@atomicLoad(std.Thread.Id, &t.stderr_mutex_locker, .unordered) != current_thread_id) {
        try mutexLock(&t.stderr_mutex);
        assert(t.stderr_mutex_lock_count == 0);
        @atomicStore(std.Thread.Id, &t.stderr_mutex_locker, current_thread_id, .unordered);
    }
    t.stderr_mutex_lock_count += 1;

    return initLockedStderr(t, terminal_mode);
}

fn tryLockStderr(userdata: ?*anyopaque, terminal_mode: ?Io.Terminal.Mode) Io.Cancelable!?Io.LockedStderr {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const current_thread_id = Thread.currentId();

    if (@atomicLoad(std.Thread.Id, &t.stderr_mutex_locker, .unordered) != current_thread_id) {
        if (!t.stderr_mutex.tryLock()) return null;
        assert(t.stderr_mutex_lock_count == 0);
        @atomicStore(std.Thread.Id, &t.stderr_mutex_locker, current_thread_id, .unordered);
    }
    t.stderr_mutex_lock_count += 1;

    return try initLockedStderr(t, terminal_mode);
}

fn initLockedStderr(t: *Threaded, terminal_mode: ?Io.Terminal.Mode) Io.Cancelable!Io.LockedStderr {
    if (!t.stderr_writer_initialized) {
        const io_t = io(t);
        if (is_windows) t.stderr_writer.file = .stderr();
        t.stderr_writer.io = io_t;
        t.stderr_writer_initialized = true;
        t.scanEnviron();
        const NO_COLOR = t.environ.exist.NO_COLOR;
        const CLICOLOR_FORCE = t.environ.exist.CLICOLOR_FORCE;
        t.stderr_mode = terminal_mode orelse try .detect(io_t, t.stderr_writer.file, NO_COLOR, CLICOLOR_FORCE);
    }
    return .{
        .file_writer = &t.stderr_writer,
        .terminal_mode = terminal_mode orelse t.stderr_mode,
    };
}

fn unlockStderr(userdata: ?*anyopaque) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (t.stderr_writer.err == null) t.stderr_writer.interface.flush() catch {};
    if (t.stderr_writer.err) |err| {
        switch (err) {
            error.Canceled => recancelInner(),
            else => {},
        }
        t.stderr_writer.err = null;
    }
    t.stderr_writer.interface.end = 0;
    t.stderr_writer.interface.buffer = &.{};

    t.stderr_mutex_lock_count -= 1;
    if (t.stderr_mutex_lock_count == 0) {
        @atomicStore(std.Thread.Id, &t.stderr_mutex_locker, Thread.invalid_id, .unordered);
        mutexUnlock(&t.stderr_mutex);
    }
}

fn processCurrentPath(userdata: ?*anyopaque, buffer: []u8) process.CurrentPathError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        var wtf16le_buf: [windows.PATH_MAX_WIDE:0]u16 = undefined;
        const n = windows.ntdll.RtlGetCurrentDirectory_U(wtf16le_buf.len * 2 + 2, &wtf16le_buf) / 2;
        if (n == 0) return error.Unexpected;
        assert(n <= wtf16le_buf.len);
        const wtf16le_slice = wtf16le_buf[0..n];
        var end_index: usize = 0;
        var it = std.unicode.Wtf16LeIterator.init(wtf16le_slice);
        while (it.nextCodepoint()) |codepoint| {
            const seq_len = std.unicode.utf8CodepointSequenceLength(codepoint) catch unreachable;
            if (end_index + seq_len >= buffer.len)
                return error.NameTooLong;
            end_index += std.unicode.wtf8Encode(codepoint, buffer[end_index..]) catch unreachable;
        }
        return end_index;
    }

    if (native_os == .wasi and !builtin.link_libc) {
        if (buffer.len == 0) return error.NameTooLong;
        buffer[0] = '.';
        return 1;
    }

    return processCurrentPathPosix(buffer);
}

fn processCurrentPathPosix(buffer: []u8) process.CurrentPathError!usize {
    const err: posix.E = if (builtin.link_libc) err: {
        const c_err = if (std.c.getcwd(buffer.ptr, buffer.len)) |_| 0 else std.c._errno().*;
        break :err @fromBackingInt(@intCast(c_err));
    } else err: {
        break :err posix.errno(posix.system.getcwd(buffer.ptr, buffer.len));
    };
    switch (err) {
        .SUCCESS => return std.mem.findScalar(u8, buffer, 0).?,
        .NOENT => return error.CurrentDirUnlinked,
        .RANGE => return error.NameTooLong,
        // On Linux, this indicates that the buffer may have been large enough, but the path
        // is too long for the syscall to handle since it exceeds PATH_MAX.
        // https://github.com/torvalds/linux/blob/e4b275531887fef7f7d8a7284bfc32f0fbbd4208/fs/d_path.c#L406-L407
        //
        // This is returned as a distinct error to differentiate it from RANGE, since
        // this NAMETOOLONG return is never recoverable by increasing the buffer size.
        // The way to recover from it would be to reconstruct the cwd piece-by-piece by e.g.
        // walking the filesystem backwards starting from "." (many libc implementations
        // of `getcwd` do this fallback-to-filesystem-walking automatically).
        .NAMETOOLONG => return error.PathExceedsLimit,
        .FAULT => |e| return errnoBug(e),
        .INVAL => |e| return errnoBug(e),
        else => return posix.unexpectedErrno(err),
    }
}

fn processSetCurrentDir(userdata: ?*anyopaque, dir: Dir) process.SetCurrentDirError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (native_os == .wasi) return error.OperationUnsupported;

    if (is_windows) {
        var dir_path_buf: [windows.PATH_MAX_WIDE]u16 = undefined;
        const dir_path = try windows_impl.GetFinalPathNameByHandle(dir.handle, .{}, &dir_path_buf);
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.RtlSetCurrentDirectory_U(&.init(dir_path))) {
            .SUCCESS => return syscall.finish(),
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .NO_MEDIA_IN_DEVICE => return syscall.fail(error.NoDevice),
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .OBJECT_PATH_SYNTAX_BAD => |err| return syscall.ntstatusBug(err),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    return fchdir(dir.handle);
}

fn processSetCurrentPath(userdata: ?*anyopaque, path: []const u8) process.SetCurrentPathError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (native_os == .wasi) return error.OperationUnsupported;

    if (is_windows) {
        var path_w_buf: [windows.PATH_MAX_WIDE]u16 = undefined;
        const len = std.unicode.calcWtf16LeLen(path) catch return error.InvalidWtf8;
        if (len > path_w_buf.len) return error.NameTooLong;
        const path_w_len = std.unicode.wtf8ToWtf16Le(&path_w_buf, path) catch |err| switch (err) {
            error.InvalidWtf8 => unreachable, // already validated
        };
        const path_w = path_w_buf[0..path_w_len];

        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.RtlSetCurrentDirectory_U(&.init(path_w))) {
            .SUCCESS => return syscall.finish(),
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .NO_MEDIA_IN_DEVICE => return syscall.fail(error.NoDevice),
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .OBJECT_PATH_SYNTAX_BAD => |err| return syscall.ntstatusBug(err),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    return chdir(path);
}

pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

pub const UnixAddress = extern union {
    any: posix.sockaddr,
    un: posix.sockaddr.un,
};

pub fn posixAddressFamily(a: *const IpAddress) posix.sa_family_t {
    return switch (a.*) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

pub fn addressFromPosix(posix_address: *const PosixAddress) IpAddress {
    return switch (posix_address.any.family) {
        posix.AF.INET => .{ .ip4 = address4FromPosix(&posix_address.in) },
        posix.AF.INET6 => .{ .ip6 = address6FromPosix(&posix_address.in6) },
        else => .{ .ip4 = .loopback(0) },
    };
}

pub fn addressToPosix(a: *const IpAddress, storage: *PosixAddress) posix.socklen_t {
    return switch (a.*) {
        .ip4 => |ip4| {
            storage.in = address4ToPosix(ip4);
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |*ip6| {
            storage.in6 = address6ToPosix(ip6);
            return @sizeOf(posix.sockaddr.in6);
        },
    };
}

pub fn addressUnixToPosix(a: *const net.UnixAddress, storage: *UnixAddress) posix.socklen_t {
    storage.un.family = posix.AF.UNIX;
    var path_len = switch (native_os) {
        .windows => @min(a.path.len, storage.un.path.len),
        else => a.path.len,
    };
    // With the AFD API, `sockaddr.un` is purely informational, so
    // use a suffix which is usually the most relevant part of a path.
    @memcpy(storage.un.path[0..path_len], a.path[a.path.len - path_len ..]);
    if (storage.un.path.len - path_len > 0) {
        @branchHint(.likely);
        storage.un.path[path_len] = 0;
        path_len += 1;
    }
    switch (native_os) {
        .windows => {
            if (storage.un.path[0] == 0) @memset(storage.un.path[path_len..], 0);
            return @sizeOf(posix.sockaddr.un);
        },
        else => return @intCast(@offsetOf(posix.sockaddr.un, "path") + path_len),
    }
}

fn address4FromPosix(in: *const posix.sockaddr.in) net.Ip4Address {
    // The network byte order address in `in.addr` is already the byte order we want.
    const addr_bytes: *const [4]u8 = @ptrCast(&in.addr);
    return .{
        .port = std.mem.bigToNative(u16, in.port),
        .bytes = addr_bytes.*,
    };
}

fn address6FromPosix(in6: *const posix.sockaddr.in6) net.Ip6Address {
    return .{
        .port = std.mem.bigToNative(u16, in6.port),
        .bytes = in6.addr,
        .flow = in6.flowinfo,
        .interface = .{ .index = in6.scope_id },
    };
}

fn address4ToPosix(a: net.Ip4Address) posix.sockaddr.in {
    // The byte order of `a.bytes` is already equivalent to a network byte order address.
    const addr_raw: *align(1) const u32 = @ptrCast(&a.bytes);
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .addr = addr_raw.*,
    };
}

fn address6ToPosix(a: *const net.Ip6Address) posix.sockaddr.in6 {
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .flowinfo = a.flow,
        .addr = a.bytes,
        .scope_id = a.interface.index,
    };
}

pub fn errnoBug(err: posix.E) Io.UnexpectedError {
    if (is_debug) std.debug.panic("programmer bug caused syscall error: {t}", .{err});
    return error.Unexpected;
}

pub fn posixSocketModeProtocol(family: posix.sa_family_t, mode: net.Socket.Mode, protocol: ?net.Protocol) !struct { u32, u32 } {
    return .{
        switch (mode) {
            .stream => posix.SOCK.STREAM,
            .dgram => posix.SOCK.DGRAM,
            .seqpacket => posix.SOCK.SEQPACKET,
            .raw => posix.SOCK.RAW,
            .rdm => if (@hasDecl(posix.SOCK, "RDM")) posix.SOCK.RDM else return error.OptionUnsupported,
        },
        if (protocol) |p| @backingInt(p) else if (is_windows) switch (family) {
            posix.AF.UNIX => switch (mode) {
                .stream => 0,
                else => return error.ProtocolUnsupportedByAddressFamily,
            },
            posix.AF.INET, posix.AF.INET6 => @backingInt(@as(net.Protocol, switch (mode) {
                .stream => .tcp,
                .dgram => .udp,
                else => return error.ProtocolUnsupportedByAddressFamily,
            })),
            else => return error.ProtocolUnsupportedByAddressFamily,
        } else 0,
    };
}

pub fn recoverableOsBugDetected() void {
    if (is_debug) unreachable;
}

pub fn clockToPosix(clock: Io.Clock) posix.clockid_t {
    return switch (clock) {
        .real => posix.CLOCK.REALTIME,
        .awake => switch (native_os) {
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => posix.CLOCK.UPTIME_RAW,
            else => posix.CLOCK.MONOTONIC,
        },
        .boot => switch (native_os) {
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => posix.CLOCK.MONOTONIC_RAW,
            // On freebsd derivatives, use MONOTONIC_FAST as currently there's
            // no precision tradeoff.
            .freebsd, .dragonfly => posix.CLOCK.MONOTONIC_FAST,
            // On linux, use BOOTTIME instead of MONOTONIC as it ticks while
            // suspended.
            .linux => posix.CLOCK.BOOTTIME,
            // On other posix systems, MONOTONIC is generally the fastest and
            // ticks while suspended.
            else => posix.CLOCK.MONOTONIC,
        },
        .cpu_process => posix.CLOCK.PROCESS_CPUTIME_ID,
        .cpu_thread => posix.CLOCK.THREAD_CPUTIME_ID,
    };
}

pub const linux_statx_request: std.os.linux.STATX = .{
    .TYPE = true,
    .MODE = true,
    .ATIME = true,
    .MTIME = true,
    .CTIME = true,
    .INO = true,
    .SIZE = true,
    .NLINK = true,
    .BLOCKS = true,
};

pub const linux_statx_check: std.os.linux.STATX = .{
    .TYPE = true,
    .MODE = true,
    .ATIME = false,
    .MTIME = true,
    .CTIME = true,
    .INO = true,
    .SIZE = true,
    .NLINK = true,
    .BLOCKS = false,
};

pub fn statFromLinux(stx: *const std.os.linux.Statx) Io.UnexpectedError!File.Stat {
    const actual_mask_int: u32 = @bitCast(stx.mask);
    const wanted_mask_int: u32 = @bitCast(linux_statx_check);
    if ((actual_mask_int | wanted_mask_int) != actual_mask_int) return error.Unexpected;

    return .{
        .inode = stx.ino,
        .nlink = stx.nlink,
        .size = stx.size,
        .permissions = .fromMode(stx.mode),
        .kind = statxKind(stx.mode),
        .atime = if (!stx.mask.ATIME) null else .{
            .nanoseconds = @intCast(@as(i128, stx.atime.sec) * std.time.ns_per_s + stx.atime.nsec),
        },
        .mtime = .{ .nanoseconds = @intCast(@as(i128, stx.mtime.sec) * std.time.ns_per_s + stx.mtime.nsec) },
        .ctime = .{ .nanoseconds = @intCast(@as(i128, stx.ctime.sec) * std.time.ns_per_s + stx.ctime.nsec) },
        .block_size = if (stx.mask.BLOCKS) stx.blksize else 1,
    };
}

pub fn statxKind(stx_mode: u16) File.Kind {
    return switch (stx_mode & std.os.linux.S.IFMT) {
        std.os.linux.S.IFDIR => .directory,
        std.os.linux.S.IFCHR => .character_device,
        std.os.linux.S.IFBLK => .block_device,
        std.os.linux.S.IFREG => .file,
        std.os.linux.S.IFIFO => .named_pipe,
        std.os.linux.S.IFLNK => .sym_link,
        std.os.linux.S.IFSOCK => .unix_domain_socket,
        else => .unknown,
    };
}

pub fn statFromPosix(st: *const posix.Stat) File.Stat {
    const atime = st.atime();
    const mtime = st.mtime();
    const ctime = st.ctime();
    return .{
        .inode = st.ino,
        .nlink = st.nlink,
        .size = @bitCast(st.size),
        .permissions = .fromMode(st.mode),
        .kind = k: {
            const m = st.mode & posix.S.IFMT;
            switch (m) {
                posix.S.IFBLK => break :k .block_device,
                posix.S.IFCHR => break :k .character_device,
                posix.S.IFDIR => break :k .directory,
                posix.S.IFIFO => break :k .named_pipe,
                posix.S.IFLNK => break :k .sym_link,
                posix.S.IFREG => break :k .file,
                posix.S.IFSOCK => break :k .unix_domain_socket,
                else => {},
            }
            if (native_os == .illumos) switch (m) {
                posix.S.IFDOOR => break :k .door,
                posix.S.IFPORT => break :k .event_port,
                else => {},
            };

            break :k .unknown;
        },
        .atime = timestampFromPosix(&atime),
        .mtime = timestampFromPosix(&mtime),
        .ctime = timestampFromPosix(&ctime),
        .block_size = @intCast(st.blksize),
    };
}

pub fn timestampFromPosix(timespec: *const posix.timespec) Io.Timestamp {
    return .{ .nanoseconds = nanosecondsFromPosix(timespec) };
}

pub fn nanosecondsFromPosix(timespec: *const posix.timespec) i96 {
    return @intCast(@as(i128, timespec.sec) * std.time.ns_per_s + timespec.nsec);
}

fn timestampToPosix(nanoseconds: i96) posix.timespec {
    return .{
        .sec = @intCast(@divFloor(nanoseconds, std.time.ns_per_s)),
        .nsec = @intCast(@mod(nanoseconds, std.time.ns_per_s)),
    };
}

pub fn setTimestampToPosix(set_ts: File.SetTimestamp) posix.timespec {
    return switch (set_ts) {
        .unchanged => posix.UTIME.OMIT,
        .now => posix.UTIME.NOW,
        .new => |t| timestampToPosix(t.nanoseconds),
    };
}

pub fn pathToPosix(file_path: []const u8, buffer: *[posix.PATH_MAX]u8) Dir.PathNameError![:0]u8 {
    if (std.mem.containsAtLeastScalar(u8, file_path, 0, 1)) return error.BadPathName;
    // >= rather than > to make room for the null byte
    if (file_path.len >= buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..file_path.len], file_path);
    buffer[file_path.len] = 0;
    return buffer[0..file_path.len :0];
}

fn doNothingSignalHandler(_: posix.SIG) callconv(.c) void {}

pub fn scanEnviron(t: *Threaded) void {
    mutexLockUncancelable(&t.mutex);
    defer mutexUnlock(&t.mutex);
    if (t.environ_initialized) return;
    t.environ.scan(t.allocator);
    t.environ_initialized = true;
}

fn processReplace(userdata: ?*anyopaque, options: process.ReplaceOptions) process.ReplaceError {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    if (!process.can_replace) return error.OperationUnsupported;

    t.scanEnviron(); // for PATH
    const PATH = t.environ.string.PATH orelse default_PATH;

    var arena_allocator = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const argv_buf = try arena.allocSentinel(?[*:0]const u8, options.argv.len, null);
    for (options.argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeSentinel(u8, arg, 0)).ptr;

    const env_block = env_block: {
        const prog_fd: i32 = -1;
        if (options.environ_map) |environ_map| break :env_block try environ_map.createPosixBlock(arena, .{
            .zig_progress_fd = prog_fd,
        });
        break :env_block try t.environ.process_environ.createPosixBlock(arena, .{
            .zig_progress_fd = prog_fd,
        });
    };

    if (is_darwin) if (darwin_impl.spawnDarwin(t, 
        .replace,
        options.exe,
        argv_buf.ptr,
        options.cwd,
        env_block,
        options.expand_arg0,
        .none,
        .inherit,
        .inherit,
        .inherit,
        options.inherit_dirs,
        options.inherit_files,
        null,
        options.start_suspended,
        PATH,
    )) |_| unreachable else |err| switch (err) {
        else => |e| return e,
        error.WouldBlock => return error.SystemResources,
        error.FileTooBig,
        error.NoSpaceLeft,
        error.PathAlreadyExists,
        error.SymLinkLoop,
        error.NetworkNotFound,
        error.PipeBusy,
        error.AntivirusInterference,
        => return error.FileNotFound,
        error.DeviceBusy,
        error.NoDevice,
        error.UnrecognizedVolume,
        error.ReadOnlyFileSystem,
        => return error.FileSystem,
        error.ResourceLimitReached => return error.SystemResources,
        error.FileLocksUnsupported => unreachable, // lock not requested
        error.InvalidWtf8 => unreachable, // windows only
        error.InvalidBatchScriptArg => unreachable, // windows only
        error.InvalidUserId => unreachable, // not supported
        error.InvalidProcessGroupId => unreachable, // passed null
        error.InvalidName => unreachable, // windows only
        error.ProcessAlreadyExec => unreachable, // linux only
    };
    return posixExec(options.exe, argv_buf.ptr, options.expand_arg0, env_block, PATH);
}

const processSpawn = switch (native_os) {
    .wasi, .emscripten, .tvos, .watchos => processSpawnUnsupported,
    .windows => windows_impl.processSpawnWindows,
    .driverkit, .ios, .maccatalyst, .macos, .visionos => darwin_impl.processSpawnDarwin,
    else => processSpawnPosix,
};

fn processSpawnUnsupported(userdata: ?*anyopaque, options: process.SpawnOptions) process.SpawnError!process.Child {
    _ = userdata;
    _ = options;
    return error.OperationUnsupported;
}

pub const Spawned = struct {
    pid: posix.pid_t,
    err_fd: posix.fd_t,
    stdin: ?File,
    stdout: ?File,
    stderr: ?File,
};

/// What `yz_spawn` (C, in the YasOS runtime) runs in the vfork child.
const YasosSpawnRequest = extern struct {
    /// The program: searched in `path_env` (when not null) unless it holds
    /// a '/'.
    file: [*:0]const u8,
    argv: [*:null]?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    path_env: ?[*:0]const u8,
    /// argv[0] becomes the path found in `path_env`.
    expand_arg0: c_int,
    /// chdir before exec; null keeps the parent's.
    cwd: ?[*:0]const u8,
    /// For fds 0, 1, 2: dup2 this onto it when >= 0; -1 inherit; -2 close.
    fds: [3]c_int,
    /// Descriptors whose FD_CLOEXEC is cleared in the child.
    inherit: [*]const c_int,
    inherit_len: c_int,
};

/// pid of the child, or -errno of what failed in it before or at exec.
extern "c" fn yz_spawn(req: *const YasosSpawnRequest) c_int;

fn yasosSpawn(
    arena: Allocator,
    options: process.SpawnOptions,
    argv: [*:null]?[*:0]const u8,
    env_block: process.Environ.PosixBlock,
    PATH: []const u8,
    pipe_fds: [3]posix.fd_t,
    dev_null_fd: posix.fd_t,
    prog_fd: posix.fd_t,
) process.SpawnError!posix.pid_t {
    if (options.uid != null or options.gid != null or options.pgid != null or options.start_suspended)
        return error.OperationUnsupported;
    var fds: [3]c_int = undefined;
    for (&fds, [_]process.SpawnOptions.StdIo{ options.stdin, options.stdout, options.stderr }, pipe_fds) |*fd, stdio, pipe_fd| {
        fd.* = switch (stdio) {
            .pipe => pipe_fd,
            .close => -2,
            .inherit => -1,
            .ignore => dev_null_fd,
            .file => |file| file.handle,
        };
    }
    var inherit: std.ArrayList(c_int) = .empty;
    for (options.inherit_dirs) |dir| try inherit.append(arena, dir.handle);
    for (options.inherit_files) |file| try inherit.append(arena, file.handle);
    if (prog_fd != -1) try inherit.append(arena, prog_fd);
    // As `posixExec`, without execveat: only paths relative to the cwd.
    const file: [*:0]const u8, const search = switch (options.exe) {
        .detect, .search => .{ argv[0].?, true },
        .path => |dir| if (dir.handle == posix.AT.FDCWD) .{ argv[0].?, false } else return error.OperationUnsupported,
        .explicit => |e| if (e.dir.handle == posix.AT.FDCWD)
            .{ (try arena.dupeSentinel(u8, e.path, 0)).ptr, false }
        else
            return error.OperationUnsupported,
        .file => return error.OperationUnsupported,
    };
    const req: YasosSpawnRequest = .{
        .file = file,
        .argv = argv,
        .envp = env_block.slice.ptr,
        .path_env = if (search) (try arena.dupeSentinel(u8, PATH, 0)).ptr else null,
        .expand_arg0 = @intFromBool(options.expand_arg0 == .expand),
        .cwd = switch (options.cwd) {
            .inherit => null,
            .path => |p| (try arena.dupeSentinel(u8, p, 0)).ptr,
            .dir => return error.OperationUnsupported, // no fchdir
        },
        .fds = fds,
        .inherit = inherit.items.ptr,
        .inherit_len = @intCast(inherit.items.len),
    };
    const rc = yz_spawn(&req);
    if (rc > 0) return rc;
    return switch (@as(posix.E, @enumFromInt(-rc))) {
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .ACCES => error.AccessDenied,
        .PERM => error.PermissionDenied,
        .NOEXEC => error.InvalidExe,
        .ISDIR => error.IsDir,
        .NOMEM, .AGAIN, .@"2BIG" => error.SystemResources,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .LOOP => error.SymLinkLoop,
        .NAMETOOLONG => error.NameTooLong,
        .NOSYS => error.OperationUnsupported,
        else => error.Unexpected,
    };
}

fn spawnPosix(t: *Threaded, options: process.SpawnOptions) process.SpawnError!Spawned {
    // The child process does need to access (one end of) these pipes. However,
    // we must initially set CLOEXEC to avoid a race condition. If another thread
    // is racing to spawn a different child process, we don't want it to inherit
    // these FDs in any scenario; that would mean that, for instance, calls to
    // `poll` from the parent would not report the child's stdout as closing when
    // expected, since the other child may retain a reference to the write end of
    // the pipe. So, we create the pipes with CLOEXEC initially. After fork, we
    // need to do something in the new child to make sure we preserve the reference
    // we want. We could use `fcntl` to remove CLOEXEC from the FD, but as it
    // turns out, we `dup2` everything anyway, so there's no need!
    const pipe_flags: posix.O = .{ .CLOEXEC = true };

    const stdin_pipe = if (options.stdin == .pipe) try pipe2(pipe_flags) else undefined;
    errdefer if (options.stdin == .pipe) {
        destroyPipe(stdin_pipe);
    };

    const stdout_pipe = if (options.stdout == .pipe) try pipe2(pipe_flags) else undefined;
    errdefer if (options.stdout == .pipe) {
        destroyPipe(stdout_pipe);
    };

    const stderr_pipe = if (options.stderr == .pipe) try pipe2(pipe_flags) else undefined;
    errdefer if (options.stderr == .pipe) {
        destroyPipe(stderr_pipe);
    };

    const any_ignore = (options.stdin == .ignore or options.stdout == .ignore or options.stderr == .ignore);
    const dev_null_fd = if (any_ignore) try getDevNullFd(t) else undefined;

    const prog_pipe: [2]posix.fd_t = if (options.progress_node.index != .none) pipe: {
        // We use CLOEXEC for the same reason as in `pipe_flags`.
        const pipe = try pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
        switch (native_os) {
            .linux => _ = posix.system.fcntl(pipe[0], posix.F.SETPIPE_SZ, @as(u32, std.Progress.max_packet_len * 2)),
            else => {},
        }
        break :pipe pipe;
    } else .{ -1, -1 };
    errdefer destroyPipe(prog_pipe);

    var arena_allocator = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // The POSIX standard does not allow malloc() between fork() and execve(),
    // and this allocator may be a libc allocator.
    // I have personally observed the child process deadlocking when it tries
    // to call malloc() due to a heap allocation between fork() and execve(),
    // in musl v1.1.24.
    // Additionally, we want to reduce the number of possible ways things
    // can fail between fork() and execve().
    // Therefore, we do all the allocation for the execve() before the fork().
    // This means we must do the null-termination of argv and env vars here.
    const argv_buf = try arena.allocSentinel(?[*:0]const u8, options.argv.len, null);
    for (options.argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeSentinel(u8, arg, 0)).ptr;

    const env_block = env_block: {
        if (options.environ_map) |environ_map| break :env_block try environ_map.createPosixBlock(arena, .{
            .zig_progress_fd = prog_pipe[1],
        });
        break :env_block try t.environ.process_environ.createPosixBlock(arena, .{
            .zig_progress_fd = prog_pipe[1],
        });
    };

    // This pipe communicates to the parent errors in the child between `fork` and `execvpe`.
    // It is closed by the child (via CLOEXEC) without writing if `execvpe` succeeds.
    const err_pipe = try pipe2(.{ .CLOEXEC = true });
    errdefer destroyPipe(err_pipe);

    t.scanEnviron(); // for PATH
    const PATH = t.environ.string.PATH orelse default_PATH;

    const pid_result: posix.pid_t = if (is_yasos)
        try yasosSpawn(arena, options, argv_buf.ptr, env_block, PATH, .{
            stdin_pipe[0], stdout_pipe[1], stderr_pipe[1],
        }, dev_null_fd, prog_pipe[1])
    else fork: {
        const rc = posix.system.fork();
        switch (posix.errno(rc)) {
            .SUCCESS => break :fork @intCast(rc),
            .AGAIN => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOSYS => return error.OperationUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    };

    if (!is_yasos and pid_result == 0) {
        defer comptime unreachable; // We are the child.
        if (Thread.current) |current_thread| current_thread.cancel_protection = .blocked;
        const ep1 = err_pipe[1];

        // Must happen before clobbering fds below.
        switch (options.cwd) {
            .inherit => {},
            .dir => |cwd| fchdir(cwd.handle) catch |err| forkBail(ep1, err),
            .path => |cwd| chdir(cwd) catch |err| forkBail(ep1, err),
        }

        for (options.inherit_dirs) |inherit_dir| switch (posix.errno(
            posix.system.fcntl(inherit_dir.handle, posix.F.SETFD, @as(u32, 0)),
        )) {
            .SUCCESS => {},
            else => |err| forkBail(ep1, posix.unexpectedErrno(err)),
        };
        for (options.inherit_files) |file| switch (posix.errno(
            posix.system.fcntl(file.handle, posix.F.SETFD, @as(u32, 0)),
        )) {
            .SUCCESS => {},
            else => |err| forkBail(ep1, posix.unexpectedErrno(err)),
        };
        if (prog_pipe[1] != -1) switch (posix.errno(
            posix.system.fcntl(prog_pipe[1], posix.F.SETFD, @as(u32, 0)),
        )) {
            .SUCCESS => {},
            else => |err| forkBail(ep1, posix.unexpectedErrno(err)),
        };
        for (
            [_]process.SpawnOptions.StdIo{ options.stdin, options.stdout, options.stderr },
            [_]posix.fd_t{ stdin_pipe[0], stdout_pipe[1], stderr_pipe[1] },
            [_]posix.fd_t{ posix.STDIN_FILENO, posix.STDOUT_FILENO, posix.STDERR_FILENO },
        ) |stdio, pipe_fd, std_fd| switch (stdio) {
            .pipe => dup2(pipe_fd, std_fd) catch |err| forkBail(ep1, err),
            .close => closeFd(std_fd),
            .inherit => {},
            .ignore => dup2(dev_null_fd, std_fd) catch |err| forkBail(ep1, err),
            .file => |file| dup2(file.handle, std_fd) catch |err| forkBail(ep1, err),
        };

        if (options.gid) |gid| {
            switch (posix.errno(posix.system.setregid(gid, gid))) {
                .SUCCESS => {},
                .AGAIN => forkBail(ep1, error.ResourceLimitReached),
                .INVAL => forkBail(ep1, error.InvalidUserId),
                .PERM => forkBail(ep1, error.PermissionDenied),
                else => forkBail(ep1, error.Unexpected),
            }
        }

        if (options.uid) |uid| {
            switch (posix.errno(posix.system.setreuid(uid, uid))) {
                .SUCCESS => {},
                .AGAIN => forkBail(ep1, error.ResourceLimitReached),
                .INVAL => forkBail(ep1, error.InvalidUserId),
                .PERM => forkBail(ep1, error.PermissionDenied),
                else => forkBail(ep1, error.Unexpected),
            }
        }

        if (options.pgid) |pid| {
            switch (posix.errno(posix.system.setpgid(0, pid))) {
                .SUCCESS => {},
                .ACCES => forkBail(ep1, error.ProcessAlreadyExec),
                .INVAL => forkBail(ep1, error.InvalidProcessGroupId),
                .PERM => forkBail(ep1, error.PermissionDenied),
                else => forkBail(ep1, error.Unexpected),
            }
        }

        if (options.start_suspended) {
            switch (posix.errno(posix.system.kill(posix.system.getpid(), .STOP))) {
                .SUCCESS => {},
                .PERM => forkBail(ep1, error.PermissionDenied),
                else => forkBail(ep1, error.Unexpected),
            }
        }

        const err = posixExec(options.exe, argv_buf.ptr, options.expand_arg0, env_block, PATH);
        forkBail(ep1, err);
    }

    const pid: posix.pid_t = @intCast(pid_result); // We are the parent.
    errdefer comptime unreachable; // The child is forked; we must not error from now on

    closeFd(err_pipe[1]); // make sure only the child holds the write end open

    if (options.stdin == .pipe) closeFd(stdin_pipe[0]);
    if (options.stdout == .pipe) closeFd(stdout_pipe[1]);
    if (options.stderr == .pipe) closeFd(stderr_pipe[1]);

    if (prog_pipe[1] != -1) closeFd(prog_pipe[1]);
    options.progress_node.setIpcFile(t, .{ .handle = prog_pipe[0], .flags = .{ .nonblocking = true } });

    return .{
        .pid = pid,
        .err_fd = err_pipe[0],
        .stdin = switch (options.stdin) {
            .pipe => .{ .handle = stdin_pipe[1], .flags = .{ .nonblocking = false } },
            else => null,
        },
        .stdout = switch (options.stdout) {
            .pipe => .{ .handle = stdout_pipe[0], .flags = .{ .nonblocking = false } },
            else => null,
        },
        .stderr = switch (options.stderr) {
            .pipe => .{ .handle = stderr_pipe[0], .flags = .{ .nonblocking = false } },
            else => null,
        },
    };
}

pub fn getDevNullFd(t: *Threaded) !posix.fd_t {
    {
        try mutexLock(&t.mutex);
        defer mutexUnlock(&t.mutex);
        if (t.null_file.fd != -1) return t.null_file.fd;
    }
    const mode: u32 = 0;
    const syscall: Syscall = try .start();
    while (true) {
        const rc = open_sym("/dev/null", .{ .ACCMODE = .RDWR }, mode);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const fresh_fd: posix.fd_t = @intCast(rc);
                mutexLockUncancelable(&t.mutex); // Another thread might have won the race.
                defer mutexUnlock(&t.mutex);
                if (t.null_file.fd != -1) {
                    closeFd(fresh_fd);
                    return t.null_file.fd;
                } else {
                    t.null_file.fd = fresh_fd;
                    return fresh_fd;
                }
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ACCES => return syscall.fail(error.AccessDenied),
            .MFILE => return syscall.fail(error.ProcessFdQuotaExceeded),
            .NFILE => return syscall.fail(error.SystemFdQuotaExceeded),
            .NODEV => return syscall.fail(error.NoDevice),
            .NOENT => return syscall.fail(error.FileNotFound),
            .NOMEM => return syscall.fail(error.SystemResources),
            .PERM => return syscall.fail(error.PermissionDenied),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

fn processSpawnPosix(userdata: ?*anyopaque, options: process.SpawnOptions) process.SpawnError!process.Child {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const spawned = try spawnPosix(t, options);
    defer closeFd(spawned.err_fd);

    // Wait for the child to report any errors in or before `execvpe`.
    if (readIntFd(spawned.err_fd)) |child_err_int| {
        const child_err: process.SpawnError = @errorCast(@errorFromInt(child_err_int));
        return child_err;
    } else |read_err| switch (read_err) {
        error.EndOfStream => {
            // Write end closed by CLOEXEC at the time of the `execvpe` call,
            // indicating success.
        },
        else => {
            // Problem reading the error from the error reporting pipe. We
            // don't know if the child is alive or dead. Better to assume it is
            // alive so the resource does not risk being leaked.
        },
    }

    return .{
        .id = spawned.pid,
        .thread_handle = {},
        .stdin = spawned.stdin,
        .stdout = spawned.stdout,
        .stderr = spawned.stderr,
        .request_resource_usage_statistics = options.request_resource_usage_statistics,
    };
}

fn childWait(userdata: ?*anyopaque, child: *process.Child) process.Child.WaitError!process.Child.Term {
    if (native_os == .wasi) unreachable;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    switch (native_os) {
        .windows => return windows_impl.childWaitWindows(child),
        else => return childWaitPosix(child),
    }
}

fn childKill(userdata: ?*anyopaque, child: *process.Child) void {
    if (native_os == .wasi) unreachable;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (is_windows) {
        windows_impl.childKillWindows(t, child, 1) catch windows_impl.childCleanupWindows(child);
    } else {
        childKillPosix(child) catch {};
        childCleanupPosix(child);
    }
}

fn childWaitPosix(child: *process.Child) process.Child.WaitError!process.Child.Term {
    defer childCleanupPosix(child);

    const pid = child.id.?;

    var ru: posix.rusage = undefined;
    const ru_ptr = if (child.request_resource_usage_statistics) &ru else null;

    if (is_yasos) {
        var status: c_int = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (posix.errno(std.c.waitpid(pid, &status, 0))) {
            .SUCCESS => {
                syscall.finish();
                if (ru_ptr) |p| {
                    p.* = std.mem.zeroes(posix.rusage);
                    child.resource_usage_statistics.rusage = p.*;
                }
                return statusToTerm(@bitCast(status));
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .CHILD => |err| return syscall.errnoBug(err), // Double-free.
            else => |err| return syscall.unexpectedErrno(err),
        };
    }

    if (have_wait4) {
        var status: if (builtin.link_libc) c_int else i32 = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (posix.errno(posix.system.wait4(pid, &status, 0, ru_ptr))) {
            .SUCCESS => {
                syscall.finish();
                if (ru_ptr) |p| child.resource_usage_statistics.rusage = p.*;
                return statusToTerm(@bitCast(status));
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .CHILD => |err| return syscall.errnoBug(err), // Double-free.
            else => |err| return syscall.unexpectedErrno(err),
        };
    }

    if (have_waitid) {
        const linux = std.os.linux; // Bypass libc which has the wrong signature.
        var info: linux.siginfo_t = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED, ru_ptr))) {
            .SUCCESS => {
                syscall.finish();
                if (ru_ptr) |p| child.resource_usage_statistics.rusage = p.*;
                const status: u32 = @bitCast(info.fields.common.second.sigchld.status);
                const code: linux.CLD = @fromBackingInt(@intCast(info.code));
                return switch (code) {
                    .EXITED => .{ .exited = @truncate(status) },
                    .KILLED, .DUMPED => .{ .signal = @fromBackingInt(@intCast(status)) },
                    .TRAPPED, .STOPPED => .{ .stopped = @fromBackingInt(@intCast(status)) },
                    _, .CONTINUED => .{ .unknown = status },
                };
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .CHILD => |err| return syscall.errnoBug(err), // Double-free.
            else => |err| return syscall.unexpectedErrno(err),
        };
    }

    var status: if (builtin.link_libc) c_int else i32 = undefined;
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
        .SUCCESS => {
            syscall.finish();
            return statusToTerm(@bitCast(status));
        },
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .CHILD => |err| return syscall.errnoBug(err), // Double-free.
        else => |err| return syscall.unexpectedErrno(err),
    };
}

pub fn statusToTerm(status: u32) process.Child.Term {
    return if (posix.W.IFEXITED(status))
        .{ .exited = posix.W.EXITSTATUS(status) }
    else if (posix.W.IFSIGNALED(status))
        .{ .signal = posix.W.TERMSIG(status) }
    else if (posix.W.IFSTOPPED(status))
        .{ .stopped = posix.W.STOPSIG(status) }
    else
        .{ .unknown = status };
}

fn childKillPosix(child: *process.Child) !void {
    // Entire function body is intentionally uncancelable.

    const pid = child.id.?;

    while (true) switch (posix.errno(posix.system.kill(pid, .TERM))) {
        .SUCCESS => break,
        .INTR => continue,
        .PERM => return error.PermissionDenied,
        .INVAL => |err| return errnoBug(err),
        .SRCH => |err| return errnoBug(err),
        else => |err| return posix.unexpectedErrno(err),
    };

    if (is_yasos) {
        var status: c_int = undefined;
        while (true) switch (posix.errno(std.c.waitpid(pid, &status, 0))) {
            .SUCCESS => return,
            .INTR => continue,
            .CHILD => |err| return errnoBug(err), // Double-free.
            else => |err| return posix.unexpectedErrno(err),
        };
    }

    if (have_wait4) {
        var status: if (builtin.link_libc) c_int else i32 = undefined;
        while (true) switch (posix.errno(posix.system.wait4(pid, &status, 0, null))) {
            .SUCCESS => return,
            .INTR => continue,
            .CHILD => |err| return errnoBug(err), // Double-free.
            else => |err| return posix.unexpectedErrno(err),
        };
    }

    if (have_waitid) {
        const linux = std.os.linux; // Bypass libc which has the wrong signature.
        var info: linux.siginfo_t = undefined;
        while (true) switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED, null))) {
            .SUCCESS => return,
            .INTR => continue,
            .CHILD => |err| return errnoBug(err), // Double-free.
            else => |err| return posix.unexpectedErrno(err),
        };
    }

    var status: if (builtin.link_libc) c_int else i32 = undefined;
    while (true) switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
        .SUCCESS => return,
        .INTR => continue,
        .CHILD => |err| return errnoBug(err), // Double-free.
        else => |err| return posix.unexpectedErrno(err),
    };
}

fn childCleanupPosix(child: *process.Child) void {
    if (child.stdin) |stdin| {
        closeFd(stdin.handle);
        child.stdin = null;
    }
    if (child.stdout) |stdout| {
        closeFd(stdout.handle);
        child.stdout = null;
    }
    if (child.stderr) |stderr| {
        closeFd(stderr.handle);
        child.stderr = null;
    }
    child.id = null;
}

/// Errors that can occur between fork() and execv()
const ForkBailError = process.SpawnError || process.ReplaceError;

/// Child of fork calls this to report an error to the fork parent. Then the
/// child exits.
fn forkBail(fd: posix.fd_t, err: ForkBailError) noreturn {
    writeIntFd(fd, @as(ErrInt, @intFromError(err))) catch {};
    // If we're linking libc, some naughty applications may have registered atexit handlers
    // which we really do not want to run in the fork child. I caught LLVM doing this and
    // it caused a deadlock instead of doing an exit syscall. In the words of Avril Lavigne,
    // "Why'd you have to go and make things so complicated?"
    if (builtin.link_libc) {
        // The `_exit` function does nothing but make the exit syscall, unlike `exit`.
        std.c._exit(1);
    } else if (native_os == .linux and !builtin.single_threaded) {
        std.os.linux.exit_group(1);
    } else {
        posix.system.exit(1);
    }
}

fn writeIntFd(fd: posix.fd_t, value: ErrInt) !void {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(u64, &buffer, value, .little);
    // Skip the cancel mechanism.
    var i: usize = 0;
    while (true) {
        const rc = posix.system.write(fd, buffer[i..].ptr, buffer.len - i);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                i += n;
                if (buffer.len - i == 0) return;
            },
            .INTR => continue,
            else => return error.SystemResources,
        }
    }
}

fn readIntFd(fd: posix.fd_t) !ErrInt {
    var buffer: [8]u8 = undefined;
    var i: usize = 0;
    while (true) {
        const rc = posix.system.read(fd, buffer[i..].ptr, buffer.len - i);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) break;
                i += n;
                continue;
            },
            .INTR => continue,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
    if (buffer.len - i != 0) return error.EndOfStream;
    return @intCast(std.mem.readInt(u64, &buffer, .little));
}

const ErrInt = @Int(.unsigned, @sizeOf(anyerror) * 8);

pub fn destroyPipe(pipe: [2]posix.fd_t) void {
    if (pipe[0] != -1) closeFd(pipe[0]);
    if (pipe[0] != pipe[1]) closeFd(pipe[1]);
}

fn getCngDevice(t: *Threaded) Io.RandomSecureError!windows.HANDLE {
    {
        try mutexLock(&t.mutex);
        defer mutexUnlock(&t.mutex);
        if (t.random_file.handle) |handle| return handle;
    }

    var fresh_handle: windows.HANDLE = undefined;
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtOpenFile(
        &fresh_handle,
        .{
            .STANDARD = .{ .SYNCHRONIZE = true },
            .SPECIFIC = .{ .FILE = .{ .READ_DATA = true } },
        },
        &.{ .ObjectName = @constCast(&windows.UNICODE_STRING.init(
            &.{ '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'C', 'N', 'G' },
        )) },
        &io_status_block,
        .VALID_FLAGS,
        .{ .IO = .SYNCHRONOUS_NONALERT },
    )) {
        .SUCCESS => {
            syscall.finish();
            mutexLockUncancelable(&t.mutex); // Another thread might have won the race.
            defer mutexUnlock(&t.mutex);
            if (t.random_file.handle) |prev_handle| {
                windows.CloseHandle(fresh_handle);
                return prev_handle;
            } else {
                t.random_file.handle = fresh_handle;
                return fresh_handle;
            }
        },
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.EntropyUnavailable), // Observed on wine 10.0
        else => return syscall.fail(error.EntropyUnavailable),
    };
}

pub fn getNamedPipeDevice(t: *Threaded) !windows.HANDLE {
    {
        try mutexLock(&t.mutex);
        defer mutexUnlock(&t.mutex);
        if (t.pipe_file.handle) |handle| return handle;
    }

    var fresh_handle: windows.HANDLE = undefined;
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtOpenFile(
        &fresh_handle,
        .{ .STANDARD = .{ .SYNCHRONIZE = true } },
        &.{
            .ObjectName = @constCast(&windows.UNICODE_STRING.init(
                &.{ '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 'a', 'm', 'e', 'd', 'P', 'i', 'p', 'e', '\\' },
            )),
        },
        &io_status_block,
        .VALID_FLAGS,
        .{ .IO = .SYNCHRONOUS_NONALERT },
    )) {
        .SUCCESS => {
            syscall.finish();
            mutexLockUncancelable(&t.mutex); // Another thread might have won the race.
            defer mutexUnlock(&t.mutex);
            if (t.pipe_file.handle) |prev_handle| {
                windows.CloseHandle(fresh_handle);
                return prev_handle;
            } else {
                t.pipe_file.handle = fresh_handle;
                return fresh_handle;
            }
        },
        .DELETE_PENDING => {
            // This error means that there *was* a file in this location on
            // the file system, but it was deleted. However, the OS is not
            // finished with the deletion operation, and so this CreateFile
            // call has failed. There is not really a sane way to handle
            // this other than retrying the creation after the OS finishes
            // the deletion.
            syscall.finish();
            try parking_sleep.sleep(.{ .duration = .{
                .raw = .fromMilliseconds(1),
                .clock = .awake,
            } });
            syscall = try .start();
            continue;
        },
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .INVALID_PARAMETER => |status| return syscall.ntstatusBug(status),
        .OBJECT_PATH_SYNTAX_BAD => |status| return syscall.ntstatusBug(status),
        .INVALID_HANDLE => |status| return syscall.ntstatusBug(status),
        .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
        .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .NO_MEDIA_IN_DEVICE => return syscall.fail(error.NoDevice),
        .SHARING_VIOLATION => return syscall.fail(error.AccessDenied),
        .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
        .PIPE_NOT_AVAILABLE => return syscall.fail(error.NoDevice),
        .FILE_IS_A_DIRECTORY => return syscall.fail(error.IsDir),
        .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
        .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
        else => |status| return syscall.unexpectedNtstatus(status),
    };
}

pub const ArgvToCommandLineError = error{ OutOfMemory, InvalidWtf8, InvalidArg0 };

fn posixExec(
    exe: process.ReplaceOptions.Exe,
    argv: [*:null]?[*:0]const u8,
    expand_arg0: process.ArgExpansion,
    env_block: process.Environ.PosixBlock,
    PATH: []const u8,
) process.ReplaceError {
    const arg0_slice = std.mem.span(argv[0].?);
    exe: switch (exe) {
        .detect => continue :exe if (std.mem.findScalar(u8, arg0_slice, '/')) |_| .{
            .path = .cwd(),
        } else .search,
        .search => {
            if (Dir.path.isAbsolute(arg0_slice)) continue :exe .{ .path = .cwd() };
            // Use of PATH_MAX here is valid as the path_buf will be passed
            // directly to the operating system in posixExecveat.
            var path_buf: [posix.PATH_MAX]u8 = undefined;
            var it = std.mem.tokenizeScalar(u8, PATH, ':');
            var err: error{ AccessDenied, FileNotFound, NotDir } = error.FileNotFound;

            while (it.next()) |search_path| {
                const path_len = search_path.len + arg0_slice.len + 1;
                if (path_buf.len < path_len + 1) return error.NameTooLong;
                @memcpy(path_buf[0..search_path.len], search_path);
                path_buf[search_path.len] = Dir.path.sep;
                @memcpy(path_buf[search_path.len + 1 ..][0..arg0_slice.len], arg0_slice);
                path_buf[path_len] = 0;
                const full_path = path_buf[0..path_len :0].ptr;
                switch (expand_arg0) {
                    .expand => argv[0] = full_path,
                    .no_expand => {},
                }
                switch (posixExecveat(posix.AT.FDCWD, full_path, argv, env_block)) {
                    error.AccessDenied, error.FileNotFound, error.NotDir => |e| switch (err) {
                        error.AccessDenied => {},
                        error.FileNotFound, error.NotDir => err = e,
                    },
                    else => |e| return e,
                }
            }
            return err;
        },
        .path => |path| return posixExecveat(path.handle, arg0_slice, argv, env_block),
        .file => |file| return posixExecveat(file.handle, null, argv, env_block),
        .explicit => |explicit| {
            var path_buffer: [posix.PATH_MAX]u8 = undefined;
            const path_posix = try pathToPosix(explicit.path, &path_buffer);
            return posixExecveat(explicit.dir.handle, path_posix, argv, env_block);
        },
    }
}

/// This function ignores PATH environment variable.
pub fn posixExecveat(
    dir: posix.fd_t,
    path: ?[*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    env_block: process.Environ.PosixBlock,
) process.ReplaceError {
    try Thread.checkCancel();
    switch (err: {
        if (path) |p| if (dir == posix.AT.FDCWD or Dir.path.isAbsoluteZ(p)) {
            break :err posix.errno(posix.system.execve(p, argv, env_block.slice.ptr));
        };
        if (comptime native_os == .linux and (!builtin.link_libc or
            (builtin.target.isGnuLibC() and builtin.target.os.version_range.linux.glibc.order(
                .{ .major = 2, .minor = 34, .patch = 0 },
            ).compare(.gte))))
        {
            switch (posix.errno(posix.system.execveat(dir, path orelse "", argv, env_block.slice.ptr, .{
                .EMPTY_PATH = path == null,
                .SYMLINK_NOFOLLOW = false,
            }))) {
                else => |err| break :err err,
                .NOSYS => {},
            }
        }
        var path_buffer: [posix.PATH_MAX]u8 = undefined;
        var path_len = realPathPosix(dir, &path_buffer) catch |err| switch (err) {
            else => |e| return e,
            error.InputOutput,
            error.FileTooBig,
            error.NoSpaceLeft,
            error.PathAlreadyExists,
            error.SymLinkLoop,
            error.NetworkNotFound,
            error.PipeBusy,
            error.AntivirusInterference,
            => return error.FileNotFound,
            error.DeviceBusy,
            error.NoDevice,
            error.UnrecognizedVolume,
            => return error.FileSystem,
        };
        if (path) |p| {
            const path_slice = std.mem.span(p);
            path_buffer[path_len] = Dir.path.sep;
            path_len += 1;
            @memcpy(path_buffer[path_len..][0..path_slice.len], path_slice);
            path_len += path_slice.len;
        }
        path_buffer[path_len] = 0;
        break :err posix.errno(
            posix.system.execve(path_buffer[0..path_len :0], argv, env_block.slice.ptr),
        );
    }) {
        .FAULT => |err| return errnoBug(err), // Bad pointer parameter.
        .@"2BIG" => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .INVAL => return error.InvalidExe,
        .NOEXEC => return error.InvalidExe,
        .IO => return error.FileSystem,
        .LOOP => return error.FileSystem,
        .ISDIR => return error.IsDir,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .TXTBSY => return error.FileBusy,
        else => |err| switch (native_os) {
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => switch (err) {
                .BADEXEC => return error.InvalidExe,
                .BADARCH => return error.InvalidExe,
                else => return posix.unexpectedErrno(err),
            },
            .linux => switch (err) {
                .LIBBAD => return error.InvalidExe,
                else => return posix.unexpectedErrno(err),
            },
            else => return posix.unexpectedErrno(err),
        },
    }
}

pub const CreatePipeOptions = windows_impl.CreatePipeOptions;
pub const windowsCreatePipe = windows_impl.windowsCreatePipe;
fn progressParentFile(userdata: ?*anyopaque) std.Progress.ParentFileError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    t.scanEnviron();
    return t.environ.zig_progress_file;
}

fn inheritParentHandle(handle: posix.fd_t) Io.InheritParentHandleError!void {
    switch (native_os) {
        .linux,
        .dragonfly,
        .freebsd,
        .netbsd,
        .openbsd,
        .illumos,
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => return setCloexec(handle),
        .windows => switch (windows.ntdll.NtSetInformationObject(
            handle,
            .HandleFlag,
            &windows.OBJECT.HANDLE_FLAG{ .INHERIT = false },
            @sizeOf(windows.OBJECT.HANDLE_FLAG),
        )) {
            .SUCCESS => return,
            else => |status| return windows.unexpectedStatus(status),
        },
        else => return error.UnsupportedOperation,
    }
}

fn inheritParentDir(userdata: ?*anyopaque, handle: Dir.Handle) Io.InheritParentHandleError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    try inheritParentHandle(handle);
    return .{ .handle = handle };
}

fn inheritParentFile(
    userdata: ?*anyopaque,
    handle: File.Handle,
    flags: File.Flags,
) Io.InheritParentHandleError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    try inheritParentHandle(handle);
    return .{ .handle = handle, .flags = flags };
}

pub fn environString(t: *Threaded, comptime name: []const u8) ?[:0]const u8 {
    t.scanEnviron();
    return @field(t.environ.string, name);
}

pub fn random(userdata: ?*anyopaque, buffer: []u8) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const thread = Thread.current orelse return randomMainThread(t, buffer);
    if (!thread.csprng.isInitialized()) {
        @branchHint(.unlikely);
        var seed: [Csprng.seed_len]u8 = undefined;
        randomMainThread(t, &seed);
        thread.csprng.rng = .init(seed);
    }
    thread.csprng.rng.fill(buffer);
}

fn randomMainThread(t: *Threaded, buffer: []u8) void {
    mutexLockUncancelable(&t.mutex);
    defer mutexUnlock(&t.mutex);

    if (!t.csprng.isInitialized()) {
        @branchHint(.unlikely);
        var seed: [Csprng.seed_len]u8 = undefined;
        {
            mutexUnlock(&t.mutex);
            defer mutexLockUncancelable(&t.mutex);

            const prev = swapCancelProtection(t, .blocked);
            defer _ = swapCancelProtection(t, prev);

            randomSecure(t, &seed) catch |err| switch (err) {
                error.Canceled => unreachable,
                error.EntropyUnavailable => fallbackSeed(t, &seed),
            };
        }
        t.csprng.rng = .init(seed);
    }

    t.csprng.rng.fill(buffer);
}

pub fn fallbackSeed(aslr_addr: ?*anyopaque, seed: *[Csprng.seed_len]u8) void {
    @memset(seed, 0);
    std.mem.writeInt(usize, seed[seed.len - @sizeOf(usize) ..][0..@sizeOf(usize)], @intFromPtr(aslr_addr), .native);
    const fallbackSeedImpl = switch (native_os) {
        .windows => windows_impl.fallbackSeedWindows,
        .wasi => if (builtin.link_libc) fallbackSeedPosix else wasi_impl.fallbackSeedWasi,
        else => fallbackSeedPosix,
    };
    fallbackSeedImpl(seed);
}

fn fallbackSeedPosix(seed: *[Csprng.seed_len]u8) void {
    std.mem.writeInt(posix.pid_t, seed[0..@sizeOf(posix.pid_t)], posix.system.getpid(), .native);
    const i_1 = @sizeOf(posix.pid_t);

    var ts: posix.timespec = undefined;
    const Sec = @TypeOf(ts.sec);
    const Nsec = @TypeOf(ts.nsec);
    const i_2 = i_1 + @sizeOf(Sec);
    switch (posix.errno(posix.system.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => {
            std.mem.writeInt(Sec, seed[i_1..][0..@sizeOf(Sec)], ts.sec, .native);
            std.mem.writeInt(Nsec, seed[i_2..][0..@sizeOf(Nsec)], ts.nsec, .native);
        },
        else => {},
    }
}

fn randomSecure(userdata: ?*anyopaque, buffer: []u8) Io.RandomSecureError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    if (is_windows) {
        if (buffer.len == 0) return;
        // ProcessPrng from bcryptprimitives.dll has the following properties:
        // * introduces a dependency on bcryptprimitives.dll, which apparently
        //   runs a test suite every time it is loaded
        // * heap allocates a 48-byte buffer, handling failure by returning NO_MEMORY in a BOOL
        //   despite the function being documented to always return TRUE
        // * reads from "\\Device\\CNG" which then seeds a per-CPU AES CSPRNG
        // Therefore, that function is avoided in favor of using the device directly.
        const cng_device = try getCngDevice(t);
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        var i: usize = 0;
        const syscall: Syscall = try .start();
        while (true) {
            const remaining_len = std.math.lossyCast(u32, buffer.len - i);
            switch (windows.ntdll.NtDeviceIoControlFile(
                cng_device,
                null,
                null,
                null,
                &io_status_block,
                windows.IOCTL.KSEC.GEN_RANDOM,
                null,
                0,
                buffer[i..].ptr,
                remaining_len,
            )) {
                .SUCCESS => {
                    i += remaining_len;
                    if (buffer.len - i == 0) {
                        return syscall.finish();
                    } else {
                        try syscall.checkCancel();
                        continue;
                    }
                },
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => return syscall.fail(error.EntropyUnavailable),
            }
        }
    }

    if (builtin.link_libc and @TypeOf(posix.system.arc4random_buf) != void) {
        if (buffer.len == 0) return;
        posix.system.arc4random_buf(buffer.ptr, buffer.len);
        return;
    }

    if (native_os == .wasi) {
        if (buffer.len == 0) return;
        const syscall: Syscall = try .start();
        while (true) switch (std.os.wasi.random_get(buffer.ptr, buffer.len)) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => return syscall.fail(error.EntropyUnavailable),
        };
    }

    if (@TypeOf(posix.system.getrandom) != void) {
        const getrandom = if (use_libc_getrandom) std.c.getrandom else std.os.linux.getrandom;
        var i: usize = 0;
        const syscall: Syscall = try .start();
        while (buffer.len - i != 0) {
            const buf = buffer[i..];
            const rc = getrandom(buf.ptr, buf.len, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    const n: usize = @intCast(rc);
                    i += n;
                    continue;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => return syscall.fail(error.EntropyUnavailable),
            }
        }
        return;
    }

    if (native_os == .emscripten) {
        if (buffer.len == 0) return;
        const err = posix.errno(std.c.getentropy(buffer.ptr, buffer.len));
        switch (err) {
            .SUCCESS => return,
            else => return error.EntropyUnavailable,
        }
    }

    if (native_os == .linux) {
        comptime assert(use_dev_urandom);
        const urandom_fd = try getRandomFd(t);

        var i: usize = 0;
        while (buffer.len - i != 0) {
            const syscall: Syscall = try .start();
            const rc = posix.system.read(urandom_fd, buffer[i..].ptr, buffer.len - i);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    const n: usize = @intCast(rc);
                    if (n == 0) return error.EntropyUnavailable;
                    i += n;
                    continue;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => return syscall.fail(error.EntropyUnavailable),
            }
        }
    }

    return error.EntropyUnavailable;
}

fn getRandomFd(t: *Threaded) Io.RandomSecureError!posix.fd_t {
    {
        try mutexLock(&t.mutex);
        defer mutexUnlock(&t.mutex);

        if (t.random_file.fd == -2) return error.EntropyUnavailable;
        if (t.random_file.fd != -1) return t.random_file.fd;
    }

    const mode: posix.mode_t = 0;

    const fd: posix.fd_t = fd: {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = openat_sym(posix.AT.FDCWD, "/dev/urandom", .{
                .ACCMODE = .RDONLY,
                .CLOEXEC = true,
            }, mode);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break :fd @intCast(rc);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => return syscall.fail(error.EntropyUnavailable),
            }
        }
    };
    errdefer closeFd(fd);

    switch (native_os) {
        .linux => {
            const sys = if (statx_use_c) std.c else std.os.linux;
            const syscall: Syscall = try .start();
            while (true) {
                var statx = std.mem.zeroes(std.os.linux.Statx);
                switch (sys.errno(sys.statx(fd, "", std.os.linux.AT.EMPTY_PATH, .{ .TYPE = true }, &statx))) {
                    .SUCCESS => {
                        syscall.finish();
                        if (!statx.mask.TYPE) return error.EntropyUnavailable;
                        mutexLockUncancelable(&t.mutex); // Another thread might have won the race.
                        defer mutexUnlock(&t.mutex);
                        if (t.random_file.fd >= 0) {
                            closeFd(fd);
                            return t.random_file.fd;
                        } else if (!posix.S.ISCHR(statx.mode)) {
                            t.random_file.fd = -2;
                            return error.EntropyUnavailable;
                        } else {
                            t.random_file.fd = fd;
                            return fd;
                        }
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => return syscall.fail(error.EntropyUnavailable),
                }
            }
        },
        else => {
            const syscall: Syscall = try .start();
            while (true) {
                var stat = std.mem.zeroes(posix.Stat);
                switch (posix.errno(fstat_sym(fd, &stat))) {
                    .SUCCESS => {
                        syscall.finish();
                        mutexLockUncancelable(&t.mutex); // Another thread might have won the race.
                        defer mutexUnlock(&t.mutex);
                        if (t.random_file.fd >= 0) {
                            closeFd(fd);
                            return t.random_file.fd;
                        } else if (!posix.S.ISCHR(stat.mode)) {
                            t.random_file.fd = -2;
                            return error.EntropyUnavailable;
                        } else {
                            t.random_file.fd = fd;
                            return fd;
                        }
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => return syscall.fail(error.EntropyUnavailable),
                }
            }
        },
    }
}

test {
    _ = @import("Threaded/test.zig");
}

const use_parking_futex = switch (native_os) {
    .windows => true, // RtlWaitOnAddress is a userland implementation anyway
    .netbsd => true, // NetBSD has `futex(2)`, but it's historically been quite buggy. TODO: evaluate whether it's okay to use now.
    .illumos => true, // Illumos has no futex mechanism
    .haiku => true, // Haiku has no futex mechanism
    else => false,
};
const use_parking_sleep = switch (native_os) {
    // On Windows, we can implement sleep either with `NtDelayExecution` (which is how `SleepEx` in
    // kernel32 works) or `NtWaitForAlertByThreadId` (thread parking). We're already using the
    // latter for futex, so we may as well use it for sleeping too, to maximise code reuse. I'm
    // also more confident that it will always correctly handle the cancelation race (so "unpark"
    // before "park" causes "park" to return immediately): it *seems* like alertable sleeps paired
    // with `NtAlertThread` do actually do this too, but there could be some caveat (e.g. it might
    // fail under some specific condition), whereas `NtWaitForAlertByThreadId` must reliably trigger
    // this behavior because `RtlWaitOnAddress` relies on it.
    .windows => true,

    // These targets have `_lwp_park`, which is superior to POSIX nanosleep because it has a better
    // cancelation mechanism.
    .netbsd,
    .illumos,
    => true,

    else => false,
};

const parking_futex = struct {
    comptime {
        assert(use_parking_futex);
    }

    const Bucket = struct {
        /// Used as a fast check for `wake` to avoid having to acquire `mutex` to discover there are no
        /// waiters. It is important for `wait` to increment this *before* checking the futex value to
        /// avoid a race.
        num_waiters: std.atomic.Value(u32),
        /// Protects `waiters`.
        mutex: ParkingMutex,
        waiters: std.DoublyLinkedList,

        /// Prevent false sharing between buckets.
        _: void align(std.atomic.cache_line) = {},

        const init: Bucket = .{ .num_waiters = .init(0), .mutex = .init, .waiters = .{} };
    };

    const Waiter = struct {
        node: std.DoublyLinkedList.Node,
        address: usize,
        tid: ParkTid,
        /// `thread_status.cancelation` is `.parked` while the thread is waiting. The single thread
        /// which atomically updates it (to `.none` or `.canceling`) is responsible for:
        ///
        /// * Removing the `Waiter` from `Bucket.waiters`
        /// * Decrementing `Bucket.num_waiters`
        /// * Unparking the thread (*after* the above, so that the `Waiter` does not go out of scope
        ///   while it is still in the `Bucket`).
        thread_status: *std.atomic.Value(Thread.Status),
        unpark_flag: if (need_unpark_flag) *UnparkFlag else void,
    };

    fn bucketForAddress(address: usize) *Bucket {
        const global = struct {
            /// Length must be a power of two. The longer this array, the less likely contention is
            /// between different futexes. This length seems like it'll provide a reasonable balance
            /// between contention and memory usage: assuming a 128-byte `Bucket` (due to cache line
            /// alignment), this uses 32 KiB of memory.
            var buckets: [256]Bucket = @splat(.init);
        };

        // Here we use Fibonacci hashing: the golden ratio can be used to evenly redistribute input
        // values across a range, giving a poor, but extremely quick to compute, hash.

        // This literal is the rounded value of '2^64 / phi' (where 'phi' is the golden ratio). The
        // shift then converts it to '2^b / phi', where 'b' is the pointer bit width.
        const fibonacci_multiplier = 0x9E3779B97F4A7C15 >> (64 - @bitSizeOf(usize));
        const hashed = address *% fibonacci_multiplier;

        comptime assert(std.math.isPowerOfTwo(global.buckets.len));
        // The high bits of `hashed` have better entropy than the low bits.
        const index = hashed >> (@bitSizeOf(usize) - @ctz(global.buckets.len));

        return &global.buckets[index];
    }

    fn wait(ptr: *const u32, expect: u32, uncancelable: bool, timeout: Io.Timeout) Io.Cancelable!void {
        const bucket = bucketForAddress(@intFromPtr(ptr));

        // Put the threadlocal access outside of the critical section.
        const opt_thread = Thread.current;
        const self_tid = getParkTid();

        var waiter: Waiter = .{
            .node = undefined, // populated by list append
            .address = @intFromPtr(ptr),
            .tid = self_tid,
            .thread_status = undefined, // populated in critical section
            .unpark_flag = undefined, // populated in critical section
        };

        var status_buf: std.atomic.Value(Thread.Status) = undefined;
        var unpark_flag_buf: UnparkFlag = unpark_flag_init;

        {
            bucket.mutex.lock();
            defer bucket.mutex.unlock();

            _ = bucket.num_waiters.fetchAdd(1, .acquire);

            if (@atomicLoad(u32, ptr, .monotonic) != expect) {
                assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
                return;
            }

            // This is in the critical section to avoid marking the thread as parked until we're
            // certain that we're actually going to park.
            waiter.thread_status, waiter.unpark_flag = status: {
                cancelable: {
                    if (uncancelable) break :cancelable;
                    const thread = opt_thread orelse break :cancelable;
                    switch (thread.cancel_protection) {
                        .blocked => break :cancelable,
                        .unblocked => {},
                    }
                    thread.futex_waiter = &waiter;
                    const old_status = thread.status.fetchOr(
                        .{ .cancelation = @fromBackingInt(@intCast(0b001)), .awaitable = .null },
                        .release, // release `thread.futex_waiter`
                    );
                    switch (old_status.cancelation) {
                        .none => {}, // status is now `.parked`
                        .canceling => {
                            // status is now `.canceled`
                            assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
                            return error.Canceled;
                        },
                        .canceled => break :cancelable, // status is still `.canceled`
                        .parked => unreachable,
                        .blocked => unreachable,
                        .blocked_alertable => unreachable,
                        .blocked_alertable_canceling => unreachable,
                        .blocked_canceling => unreachable,
                    }
                    // We could now be unparked for a cancelation at any time!
                    break :status .{ &thread.status, if (need_unpark_flag) &thread.unpark_flag };
                }
                // This is an uncancelable wait, so just use `status_buf`. Note that the value of
                // `status_buf.awaitable` is irrelevant because this is only visible to futex code,
                // while only cancelation cares about `awaitable`.
                status_buf.raw = .{ .cancelation = .parked, .awaitable = .null };
                break :status .{ &status_buf, if (need_unpark_flag) &unpark_flag_buf };
            };

            bucket.waiters.append(&waiter.node);
        }

        if (park(timeout, ptr, waiter.unpark_flag)) {
            // We were unparked by either `wake` or cancelation, so our current status is either
            // `.none` or `.canceling`. In either case, they've already removed `waiter` from
            // `bucket`, so we have nothing more to do!
        } else |err| switch (err) {
            error.Timeout => {
                // We're not out of the woods yet: an unpark could race with the timeout.
                const old_status = waiter.thread_status.fetchAnd(
                    .{ .cancelation = @fromBackingInt(@intCast(0b110)), .awaitable = .all_ones },
                    .monotonic,
                );
                switch (old_status.cancelation) {
                    .parked => {
                        // No race. It is our responsibility to remove `waiter` from `bucket`.
                        // New status is `.none`.
                        bucket.mutex.lock();
                        defer bucket.mutex.unlock();
                        bucket.waiters.remove(&waiter.node);
                        assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
                    },
                    .none, .canceling => {
                        // Race condition: the timeout was reached, then `wake` or a canceler tried
                        // to unpark us. Whoever did that will remove us from `bucket`. Wait for
                        // that (and drop the unpark request in doing so).
                        // New status is `.none` or `.canceling` respectively.
                        park(.none, ptr, waiter.unpark_flag) catch |e| switch (e) {
                            error.Timeout => unreachable,
                        };
                    },
                    .canceled => unreachable,
                    .blocked => unreachable,
                    .blocked_alertable => unreachable,
                    .blocked_canceling => unreachable,
                    .blocked_alertable_canceling => unreachable,
                }
            },
        }
    }

    fn wake(ptr: *const u32, max_waiters: u32) void {
        if (max_waiters == 0) return;

        const bucket = bucketForAddress(@intFromPtr(ptr));

        // To ensure the store to `ptr` is ordered before this check, we effectively want a `.release`
        // load, but that doesn't exist in the C11 memory model, so emulate it with a non-mutating rmw.
        if (bucket.num_waiters.fetchAdd(0, .release) == 0) {
            @branchHint(.likely);
            return; // no waiters
        }

        // Waiters removed from the linked list under the mutex so we can unpark their threads outside
        // of the critical section. This forms a singly-linked list of waiters using `Waiter.node.next`.
        var waking_head: ?*std.DoublyLinkedList.Node = null;
        {
            bucket.mutex.lock();
            defer bucket.mutex.unlock();

            var num_removed: u32 = 0;
            var it = bucket.waiters.first;
            while (num_removed < max_waiters) {
                const waiter: *Waiter = @fieldParentPtr("node", it orelse break);
                it = waiter.node.next;
                if (waiter.address != @intFromPtr(ptr)) continue;
                const old_status = waiter.thread_status.fetchAnd(
                    .{ .cancelation = @fromBackingInt(@intCast(0b110)), .awaitable = .all_ones },
                    .monotonic,
                );
                switch (old_status.cancelation) {
                    .parked => {}, // state updated to `.none`
                    .none => continue, // race with timeout; they are about to lock `bucket.mutex` and remove themselves from the bucket
                    .canceling => continue, // race with a canceler who hasn't called `removeCanceledWaiter` yet
                    .canceled => unreachable,
                    .blocked => unreachable,
                    .blocked_alertable => unreachable,
                    .blocked_alertable_canceling => unreachable,
                    .blocked_canceling => unreachable,
                }
                // We're waking this waiter. Remove them from the bucket and add them to our local list.
                bucket.waiters.remove(&waiter.node);
                waiter.node.next = waking_head;
                waking_head = &waiter.node;
                num_removed += 1;
            }
            _ = bucket.num_waiters.fetchSub(num_removed, .monotonic);
        }

        var unpark_buf: [128]UnparkTid = undefined;
        var unpark_len: usize = 0;

        // Finally, unpark the threads.
        while (waking_head) |node| {
            waking_head = node.next;
            const waiter: *Waiter = @fieldParentPtr("node", node);
            unpark_buf[unpark_len] = waiter.tid;
            if (need_unpark_flag) setUnparkFlag(waiter.unpark_flag);
            unpark_len += 1;
            if (unpark_len == unpark_buf.len) {
                unpark(&unpark_buf, ptr);
                unpark_len = 0;
            }
        }
        if (unpark_len > 0) {
            unpark(unpark_buf[0..unpark_len], ptr);
        }
    }

    fn removeCanceledWaiter(waiter: *Waiter) void {
        const bucket = bucketForAddress(waiter.address);
        bucket.mutex.lock();
        defer bucket.mutex.unlock();
        bucket.waiters.remove(&waiter.node);
        assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
    }
};
pub const parking_sleep = struct {
    comptime {
        assert(use_parking_sleep);
    }
    pub fn sleep(timeout: Io.Timeout) Io.Cancelable!void {
        const opt_thread = Thread.current;
        cancelable: {
            const thread = opt_thread orelse break :cancelable;
            switch (thread.cancel_protection) {
                .blocked => break :cancelable,
                .unblocked => {},
            }
            thread.futex_waiter = null;
            {
                const old_status = thread.status.fetchOr(
                    .{ .cancelation = @fromBackingInt(@intCast(0b001)), .awaitable = .null },
                    .release, // release `thread.futex_waiter`
                );
                switch (old_status.cancelation) {
                    .none => {}, // status is now `.parked`
                    .canceling => return error.Canceled, // status is now `.canceled`
                    .canceled => break :cancelable, // status is still `.canceled`
                    .parked => unreachable,
                    .blocked => unreachable,
                    .blocked_alertable => unreachable,
                    .blocked_alertable_canceling => unreachable,
                    .blocked_canceling => unreachable,
                }
            }
            if (park(timeout, null, if (need_unpark_flag) &thread.unpark_flag)) {
                // The only reason this could possibly happen is cancelation.
                const old_status = thread.status.load(.monotonic);
                assert(old_status.cancelation == .canceling);
                thread.status.store(
                    .{ .cancelation = .canceled, .awaitable = old_status.awaitable },
                    .monotonic,
                );
                return error.Canceled;
            } else |err| switch (err) {
                error.Timeout => {
                    // We're not out of the woods yet: an unpark could race with the timeout.
                    const old_status = thread.status.fetchAnd(
                        .{ .cancelation = @fromBackingInt(@intCast(0b110)), .awaitable = .all_ones },
                        .monotonic,
                    );
                    switch (old_status.cancelation) {
                        .parked => return, // No race; new status is `.none`
                        .canceling => {
                            // Race condition: the timeout was reached, then someone tried to unpark
                            // us for a cancelation. Whoever did that will have called `unpark`, so
                            // drop that unpark request by waiting for it.
                            // Status is still `.canceling`.
                            park(.none, null, if (need_unpark_flag) &thread.unpark_flag) catch |e| switch (e) {
                                error.Timeout => unreachable,
                            };
                            return;
                        },
                        .none => unreachable,
                        .canceled => unreachable,
                        .blocked => unreachable,
                        .blocked_alertable => unreachable,
                        .blocked_canceling => unreachable,
                        .blocked_alertable_canceling => unreachable,
                    }
                },
            }
        }

        // Uncancelable sleep; we expect not to be manually unparked.

        // On systems where parking the thread requires a one-time setup operation (e.g. creating a
        // semaphore), we need to ensure that setup is done before we call `park`.
        _ = getParkTid();
        var dummy_flag: UnparkFlag = unpark_flag_init;
        if (park(timeout, null, if (need_unpark_flag) &dummy_flag)) {
            unreachable; // unexpected unpark
        } else |err| switch (err) {
            error.Timeout => return,
        }
    }
};
const ParkingMutex = struct {
    state: std.atomic.Value(State),

    const init: ParkingMutex = .{ .state = .init(.unlocked) };

    comptime {
        assert(use_parking_futex);
    }

    const State = enum(usize) {
        unlocked = 1,
        /// This value is intentionally 0 so that `waiter` returns `null`.
        locked_once = 0,
        /// Contended; value is a `*Waiter`.
        _,
        /// Returns the head of the waiter list. Illegal to call if `s == .unlocked`.
        fn waiter(s: State) ?*Waiter {
            return @ptrFromInt(@backingInt(s));
        }
        /// Returns a locked state where `w` is contending the lock.
        /// If `w` is `null`, returns `.locked_once`.
        fn fromWaiter(w: ?*Waiter) State {
            return @fromBackingInt(@intCast(@intFromPtr(w)));
        }
    };
    const Waiter = struct {
        unpark_flag: UnparkFlag,
        /// Never modified once the `Waiter` is in the linked list.
        next: ?*Waiter,
        /// Never modified once the `Waiter` is in the linked list.
        tid: ParkTid,
    };
    fn lock(m: *ParkingMutex) void {
        state: switch (State.unlocked) { // assume 'unlocked' to optimize for uncontended case
            .unlocked => continue :state m.state.cmpxchgWeak(
                .unlocked,
                .locked_once,
                .acquire, // acquire lock
                .monotonic,
            ) orelse {
                @branchHint(.likely);
                return;
            },

            .locked_once, _ => |last_state| {
                const old_waiter = last_state.waiter();
                const self_tid = getParkTid();
                var waiter: Waiter = .{
                    .next = old_waiter,
                    .unpark_flag = unpark_flag_init,
                    .tid = self_tid,
                };
                if (m.state.cmpxchgWeak(
                    .fromWaiter(old_waiter),
                    .fromWaiter(&waiter),
                    .release, // release `waiter`
                    .monotonic,
                )) |new_state| {
                    continue :state new_state;
                }
                // We're now in the list of waiters---park until we're given the lock.
                park(.none, m, if (need_unpark_flag) &waiter.unpark_flag) catch |err| switch (err) {
                    error.Timeout => unreachable,
                };
                return;
            },
        }
    }
    fn unlock(m: *ParkingMutex) void {
        state: switch (State.locked_once) { // assume 'locked_once' to optimize for uncontended case
            .unlocked => unreachable, // we hold the lock

            .locked_once => continue :state m.state.cmpxchgWeak(
                .locked_once,
                .unlocked,
                .release, // release lock
                .acquire, // acquire any `Waiter` memory
            ) orelse {
                @branchHint(.likely);
                return;
            },

            _ => |last_state| {
                // The logic here does not have ABA problems, and does some accesses non-atomically,
                // because `Waiter.next` is owned by the lock holder (that's us!) once the waiter is
                // in the linked list, up until we unpark the waiter.

                // Run through the waiter list to the end to ensure fairness. This is obviously not
                // ideal, but it shouldn't be a big deal in practice provided the critical section
                // is fairly small (so we won't get too many threads contending the mutex at once).
                // There's a *chance* we could get away with a LIFO queue for our use case, but I
                // don't wanna risk that.
                var parent: ?*Waiter = null;
                var waiter: *Waiter = last_state.waiter().?;
                while (waiter.next) |next| {
                    parent = waiter;
                    waiter = next;
                }
                // `waiter` is next in line for the lock. Remove them from the list.
                if (parent) |p| {
                    assert(p.next == waiter);
                    p.next = null;
                } else {
                    // We're waking the last waiter, so clear the list head.
                    if (m.state.cmpxchgWeak(
                        .fromWaiter(last_state.waiter().?),
                        .locked_once,
                        .acquire,
                        .acquire, // acquire any new `Waiter` memory
                    )) |new_state| {
                        continue :state new_state;
                    }
                }
                // Now we're ready to actually hand the lock over to them.
                const tid = waiter.tid; // load before the unpark below potentially invalidates `waiter`
                if (need_unpark_flag) setUnparkFlag(&waiter.unpark_flag);
                unpark(&.{tid}, m);
                return;
            },
        }
    }
};

/// The API on NetBSD and Illumos sucks and can unpark spuriously (well, it *can't*, but signals
/// cause an indistinguishable unblock, and libpthread really likes to leave unparks pending).
/// As such, on these targets only, we need to pass around a flag to track whether a thread is
/// "actually" being unparked.
const need_unpark_flag = switch (native_os) {
    .netbsd, .illumos => true,
    else => false,
};
const UnparkFlag = if (need_unpark_flag) std.atomic.Value(bool) else void;
const unpark_flag_init: UnparkFlag = if (need_unpark_flag) .init(false);
/// Must be called before `unpark`. After this function is called, the thread may be unparked at any
/// time, so the caller must not reference values on its stack.
fn setUnparkFlag(f: *UnparkFlag) void {
    f.store(true, .release);
}

/// The type passed into `unpark` for the thread ID. You'd think this was just a `std.Thread.Id`,
/// but it seems that someone at Microsoft forgot how big their TIDs are supposed to be.
const UnparkTid = switch (native_os) {
    .windows => usize,
    else => ParkTid,
};

const ParkTid = switch (native_os) {
    .haiku => std.c.sem_id,
    else => std.Thread.Id,
};

threadlocal var park_sem: std.c.sem_id = -1;

fn getParkTid() ParkTid {
    switch (native_os) {
        .haiku => {
            if (park_sem == -1) {
                park_sem = std.c._kern_create_sem(0, null);
                if (park_sem < 0) @panic("_kern_create_sem failed");
                _ = std.c.on_exit_thread(destroyParkSem, null);
            }
            return park_sem;
        },
        else => {
            return if (Thread.current) |thread| thread.id else std.Thread.getCurrentId();
        },
    }
}

fn destroyParkSem(_: ?*anyopaque) callconv(.c) void {
    _ = std.c._kern_delete_sem(park_sem);
}

fn park(
    timeout: Io.Timeout,
    /// This value has no semantic effect, but may allow the OS to optimize the operation.
    addr_hint: ?*const anyopaque,
    unpark_flag: if (need_unpark_flag) *UnparkFlag else void,
) error{Timeout}!void {
    comptime assert(use_parking_futex or use_parking_sleep);
    switch (native_os) {
        .windows => {
            const raw_timeout = windows_impl.timeoutToWindowsInterval(timeout);
            // `RtlWaitOnAddress` passes the futex address in as the first argument to this call,
            // but it's unclear what that actually does, especially since `NtAlertThreadByThreadId`
            // does *not* accept the address so the kernel can't really be using it as a hint. An
            // old Microsoft blog post discusses a more traditional futex-like mechanism in the
            // kernel which definitely isn't how `RtlWaitOnAddress` works today:
            //
            // https://devblogs.microsoft.com/oldnewthing/20160826-00/?p=94185
            //
            // ...so it's possible this argument is simply a remnant which no longer does anything
            // (perhaps the implementation changed during development but someone forgot to remove
            // this parameter). However, to err on the side of caution, let's match the behavior of
            // `RtlWaitOnAddress` and pass the pointer, in case the kernel ever does something
            // stupid such as trying to dereference it.
            switch (windows.ntdll.NtWaitForAlertByThreadId(
                addr_hint,
                if (raw_timeout) |*t| t else null,
            )) {
                .ALERTED => return,
                .TIMEOUT => return error.Timeout,
                else => unreachable,
            }
        },
        .netbsd => {
            var ts_buf: posix.timespec = undefined;
            const ts: ?*posix.timespec, const abstime: bool, const clock_real: bool = switch (timeout) {
                .none => .{ null, false, false },
                .deadline => |timestamp| timeout: {
                    ts_buf = timestampToPosix(timestamp.raw.nanoseconds);
                    break :timeout .{ &ts_buf, true, timestamp.clock == .real };
                },
                .duration => |duration| timeout: {
                    ts_buf = timestampToPosix(duration.raw.nanoseconds);
                    break :timeout .{ &ts_buf, false, duration.clock == .real };
                },
            };
            // It's okay to pass the same timeout in a loop. If it's a duration, the OS actually
            // writes the remaining time into the buffer when the syscall returns.
            while (!unpark_flag.swap(false, .acquire)) {
                switch (posix.errno(std.c._lwp_park(
                    if (clock_real) .REALTIME else .MONOTONIC,
                    .{ .ABSTIME = abstime },
                    ts,
                    0,
                    addr_hint,
                    null,
                ))) {
                    .SUCCESS, .ALREADY, .INTR => {},
                    .TIMEDOUT => return error.Timeout,
                    .INVAL => unreachable,
                    .SRCH => unreachable,
                    else => unreachable,
                }
            }
        },
        .illumos => @panic("TODO: illumos lwp_park"),
        .haiku => {
            const timeout_flags: u32, const timeout_us = switch (timeout) {
                .none => .{ 0, 0 },
                .deadline => |deadline| .{
                    if (deadline.clock == .real) std.c.B_ABSOLUTE_TIMEOUT | std.c.B_TIMEOUT_REAL_TIME_BASE else std.c.B_ABSOLUTE_TIMEOUT,
                    deadline.raw.toMicroseconds(),
                },
                .duration => |duration| .{
                    if (duration.clock == .real) std.c.B_ABSOLUTE_TIMEOUT | std.c.B_TIMEOUT_REAL_TIME_BASE else std.c.B_ABSOLUTE_TIMEOUT,
                    nowPosix(duration.clock).addDuration(duration.raw).toMicroseconds(),
                },
            };
            while (true) {
                switch (std.c._kern_acquire_sem_etc(park_sem, 1, timeout_flags, timeout_us)) {
                    0 => return,
                    std.c.E.B_TIMED_OUT => return error.Timeout,
                    std.c.E.B_INTERRUPTED => {},
                    else => unreachable,
                }
            }
        },
        else => comptime unreachable,
    }
}
/// `addr_hint` has no semantic effect, but may allow the OS to optimize this operation.
fn unpark(tids: []const UnparkTid, addr_hint: ?*const anyopaque) void {
    comptime assert(use_parking_futex or use_parking_sleep);
    switch (native_os) {
        .windows => {
            // TODO: this condition is currently disabled because mingw-w64 does not contain this
            // symbol. Once it's added, enable this check to use the new bulk API where possible.
            if (false and (builtin.os.version_range.windows.isAtLeast(.win11_dt) orelse false)) {
                _ = windows.ntdll.NtAlertMultipleThreadByThreadId(tids.ptr, @intCast(tids.len), null, null);
            } else {
                for (tids) |tid| {
                    _ = windows.ntdll.NtAlertThreadByThreadId(@intCast(tid));
                }
            }
        },
        .netbsd => {
            switch (posix.errno(std.c._lwp_unpark_all(@ptrCast(tids.ptr), tids.len, addr_hint))) {
                .SUCCESS => return,
                // For errors, fall through to a loop over `tids`, though this is only expected to
                // be possible for ENOMEM (even that is questionable) and ESRCH (see comment below).
                .SRCH => {},
                .FAULT => recoverableOsBugDetected(),
                .INVAL => recoverableOsBugDetected(),
                .NOMEM => {},
                else => recoverableOsBugDetected(),
            }
            for (tids) |tid| {
                switch (posix.errno(std.c._lwp_unpark(@bitCast(tid), addr_hint))) {
                    .SUCCESS => {},
                    .SRCH => {
                        // This can happen in a rare race: the thread might have been spuriously
                        // unparked, so already observed the changing status, and from there have
                        // exited. That's okay, because the thread has woken up like we wanted.
                    },
                    else => recoverableOsBugDetected(),
                }
            }
        },
        .illumos => @panic("TODO: illumos lwp_unpark"),
        .haiku => {
            for (tids) |tid| {
                switch (std.c._kern_release_sem_etc(tid, 1, 0)) {
                    0 => {},
                    else => recoverableOsBugDetected(),
                }
            }
        },
        else => comptime unreachable,
    }
}

pub const PipeError = error{
    SystemFdQuotaExceeded,
    ProcessFdQuotaExceeded,
} || Io.UnexpectedError;

pub fn pipe2(flags: posix.O) PipeError![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;

    if (@TypeOf(posix.system.pipe2) != void) {
        switch (posix.errno(posix.system.pipe2(&fds, flags))) {
            .SUCCESS => return fds,
            .INVAL => |err| return errnoBug(err), // Invalid flags
            .NFILE => return error.SystemFdQuotaExceeded,
            .MFILE => return error.ProcessFdQuotaExceeded,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    switch (posix.errno(posix.system.pipe(&fds))) {
        .SUCCESS => {},
        .NFILE => return error.SystemFdQuotaExceeded,
        .MFILE => return error.ProcessFdQuotaExceeded,
        else => |err| return posix.unexpectedErrno(err),
    }
    errdefer {
        closeFd(fds[0]);
        closeFd(fds[1]);
    }

    // https://github.com/ziglang/zig/issues/18882
    if (@as(u32, @bitCast(flags)) == 0) return fds;

    // CLOEXEC is special, it's a file descriptor flag and must be set using
    // F.SETFD.
    if (flags.CLOEXEC) for (fds) |fd| {
        switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFD, @as(u32, posix.FD_CLOEXEC)))) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
    };

    const new_flags: u32 = f: {
        var new_flags = flags;
        new_flags.CLOEXEC = false;
        break :f @bitCast(new_flags);
    };

    // Set every other flag affecting the file status using F.SETFL.
    if (new_flags != 0) for (fds) |fd| {
        switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, new_flags))) {
            .SUCCESS => {},
            .INVAL => |err| return errnoBug(err),
            else => |err| return posix.unexpectedErrno(err),
        }
    };

    return fds;
}

pub const DupError = error{
    ProcessFdQuotaExceeded,
    SystemResources,
} || Io.UnexpectedError || Io.Cancelable;

pub fn dup2(old_fd: posix.fd_t, new_fd: posix.fd_t) DupError!void {
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.dup2(old_fd, new_fd))) {
        .SUCCESS => return syscall.finish(),
        .BUSY, .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .INVAL => |err| return syscall.errnoBug(err), // invalid parameters
        .BADF => |err| return syscall.errnoBug(err), // use after free
        .MFILE => return syscall.fail(error.ProcessFdQuotaExceeded),
        .NOMEM => return syscall.fail(error.SystemResources),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

pub const FchdirError = error{
    AccessDenied,
    NotDir,
    FileSystem,
} || Io.Cancelable || Io.UnexpectedError;

pub fn fchdir(fd: posix.fd_t) FchdirError!void {
    if (fd == posix.AT.FDCWD) return;
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.fchdir(fd))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .ACCES => return syscall.fail(error.AccessDenied),
        .NOTDIR => return syscall.fail(error.NotDir),
        .IO => return syscall.fail(error.FileSystem),
        .BADF => |err| return syscall.errnoBug(err),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

pub const ChdirError = error{
    AccessDenied,
    FileSystem,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotDir,
    BadPathName,
} || Io.Cancelable || Io.UnexpectedError;

pub fn chdir(dir_path: []const u8) ChdirError!void {
    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const dir_path_posix = try pathToPosix(dir_path, &path_buffer);
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.chdir(dir_path_posix))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .ACCES => return syscall.fail(error.AccessDenied),
        .IO => return syscall.fail(error.FileSystem),
        .LOOP => return syscall.fail(error.SymLinkLoop),
        .NAMETOOLONG => return syscall.fail(error.NameTooLong),
        .NOENT => return syscall.fail(error.FileNotFound),
        .NOMEM => return syscall.fail(error.SystemResources),
        .NOTDIR => return syscall.fail(error.NotDir),
        .ILSEQ => return syscall.fail(error.BadPathName),
        .FAULT => |err| return syscall.errnoBug(err),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

fn fileMemoryMapCreate(
    userdata: ?*anyopaque,
    file: File,
    options: File.MemoryMap.CreateOptions,
) File.MemoryMap.CreateError!File.MemoryMap {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const offset = options.offset;
    const len = options.len;

    if (!t.disable_memory_mapping) {
        if (createFileMap(file, options.protection, offset, options.populate, len)) |result| {
            return result;
        } else |err| switch (err) {
            error.Unseekable, error.Canceled, error.AccessDenied => |e| return e,
            error.OperationUnsupported => {},
            else => {
                if (builtin.mode == .debug)
                    std.log.warn("memory mapping failed with {t}, falling back to file operations", .{err});
            },
        }
    }

    const gpa = t.allocator;
    const page_size = std.heap.pageSize();
    const alignment: Alignment = .fromByteUnits(page_size);
    const memory = m: {
        const ptr = gpa.rawAlloc(len, alignment, @returnAddress()) orelse return error.OutOfMemory;
        break :m ptr[0..len];
    };
    errdefer gpa.rawFree(memory, alignment, @returnAddress());

    if (!options.undefined_contents) try mmSyncRead(file, memory, offset);

    return .{
        .file = file,
        .offset = offset,
        .memory = @alignCast(memory),
        .section = null,
    };
}

const CreateFileMapError = error{
    /// MaximumSize is greater than the system-defined maximum for sections, or
    /// greater than the specified file and the section is not writable.
    SectionOversize,
    /// A file descriptor refers to a non-regular file. Or a file mapping was requested,
    /// but the file descriptor is not open for reading. Or `MAP.SHARED` was requested
    /// and `PROT_WRITE` is set, but the file descriptor is not open in `RDWR` mode.
    /// Or `PROT_WRITE` is set, but the file is append-only.
    AccessDenied,
    /// The `prot` argument asks for `PROT_EXEC` but the mapped area belongs to a file on
    /// a filesystem that was mounted no-exec.
    PermissionDenied,
    FileBusy,
    LockedMemoryLimitExceeded,
    OperationUnsupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    OutOfMemory,
    MappingAlreadyExists,
    Unseekable,
    LockViolation,
} || Io.Cancelable || Io.UnexpectedError;

fn createFileMap(
    file: File,
    protection: process.MemoryProtection,
    offset: u64,
    populate: bool,
    len: usize,
) CreateFileMapError!File.MemoryMap {
    if (is_windows) {
        try Thread.checkCancel();

        var section = windows.INVALID_HANDLE_VALUE;
        const section_size: windows.LARGE_INTEGER = @intCast(len);
        const page = windows.PAGE.fromProtection(protection) orelse return error.AccessDenied;
        switch (windows.ntdll.NtCreateSection(
            &section,
            .{
                .SPECIFIC = .{ .SECTION = .{
                    .QUERY = true,
                    .MAP_WRITE = protection.write,
                    .MAP_READ = protection.read,
                    .MAP_EXECUTE = protection.execute,
                    .EXTEND_SIZE = true,
                } },
                .STANDARD = .{ .RIGHTS = .REQUIRED },
            },
            null,
            &section_size,
            page,
            .{
                // Required when calling NtCreateSection with a file handle, otherwise
                // this call will fail with INVALID_PARAMETER_6. The higher level
                // `CreateFileMapping` function will set this bit for you when it
                // calls NtCreateSection.
                .COMMIT = true,
            },
            file.handle,
        )) {
            .SUCCESS => {},
            .FILE_LOCK_CONFLICT => return error.LockViolation,
            .INVALID_FILE_FOR_SECTION => return error.OperationUnsupported,
            .ACCESS_DENIED => return error.AccessDenied,
            .SECTION_TOO_BIG => return error.SectionOversize,
            else => |status| return windows.unexpectedStatus(status),
        }
        var contents_ptr: ?[*]align(std.heap.page_size_min) u8 = null;
        var contents_len = len;
        switch (windows.ntdll.NtMapViewOfSection(
            section,
            windows.current_process,
            @ptrCast(&contents_ptr),
            null,
            0,
            null,
            &contents_len,
            .Unmap,
            .{},
            page,
        )) {
            .SUCCESS => {},
            .CONFLICTING_ADDRESSES => return error.MappingAlreadyExists,
            .SECTION_PROTECTION => return error.PermissionDenied,
            .ACCESS_DENIED => return error.AccessDenied,
            .INVALID_VIEW_SIZE => |status| return windows.statusBug(status),
            else => |status| return windows.unexpectedStatus(status),
        }
        if (builtin.mode == .debug) {
            const page_size = std.heap.pageSize();
            const alignment: Alignment = .fromByteUnits(page_size);
            assert(contents_len == alignment.forward(len));
        }
        if (populate) {
            const addresses = [_]windows.MEMORY_RANGE_ENTRY{
                .{ .VirtualAddress = contents_ptr.?, .NumberOfBytes = len },
            };
            var info: windows.VIRTUAL_MEMORY.MEMORY_PREFETCH_INFORMATION = .{
                .Flags = .{
                    // This flag requires Windows 11 >= 24H4. On earlier versions, this being set
                    // will cause NtSetInformationVirtualMemory to fail with INVALID_PARAMETER_5.
                    .TO_WORKING_SET = false,
                },
            };
            // There has been some doubt about the efficacy of this function:
            // https://github.com/microsoft/Windows-Dev-Performance/issues/108
            //
            // However, through testing it has been shown that, if the mapped file is not
            // in the cache, calling this function can turn what might otherwise be hard
            // faults into soft faults. Either way, it's still good to call it in order to
            // accurately reflect our intent.
            switch (windows.ntdll.NtSetInformationVirtualMemory(
                windows.current_process,
                .Prefetch,
                1,
                &addresses,
                &info,
                @sizeOf(windows.VIRTUAL_MEMORY.MEMORY_PREFETCH_INFORMATION),
            )) {
                .SUCCESS => {},
                else => |status| return windows.unexpectedStatus(status),
            }
        }
        return .{
            .file = file,
            .offset = offset,
            .memory = contents_ptr.?[0..len],
            .section = section,
        };
    } else if (have_mmap) {
        const prot: posix.PROT = .{
            .READ = protection.read,
            .WRITE = protection.write,
            .EXEC = protection.execute,
        };
        const flags: posix.MAP = switch (native_os) {
            .linux => .{
                .TYPE = .SHARED_VALIDATE,
                .POPULATE = populate,
            },
            else => .{
                .TYPE = .SHARED,
            },
        };

        const page_align = std.heap.page_size_min;

        const contents = while (true) {
            const syscall: Syscall = try .start();
            const casted_offset = std.math.cast(i64, offset) orelse return error.Unseekable;
            const rc = mmap_sym(null, len, prot, flags, file.handle, casted_offset);
            syscall.finish();
            const err: posix.E = if (builtin.link_libc) e: {
                if (rc != std.c.MAP_FAILED) {
                    break @as([*]align(page_align) u8, @ptrCast(@alignCast(rc)))[0..len];
                }
                break :e @fromBackingInt(@intCast(posix.system._errno().*));
            } else e: {
                const err = posix.errno(rc);
                if (err == .SUCCESS) {
                    break @as([*]align(page_align) u8, @ptrFromInt(rc))[0..len];
                }
                break :e err;
            };
            switch (err) {
                .SUCCESS => unreachable,
                .INTR => continue,
                .ACCES => return error.AccessDenied,
                .AGAIN => return error.LockedMemoryLimitExceeded,
                .EXIST => return error.MappingAlreadyExists,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NODEV => return error.OperationUnsupported,
                .NOMEM => return error.OutOfMemory,
                .PERM => return error.PermissionDenied,
                .TXTBSY => return error.FileBusy,
                .OVERFLOW => return error.Unseekable,
                .BADF => return errnoBug(err), // Always a race condition.
                .INVAL => return errnoBug(err), // Invalid parameters to mmap()
                .OPNOTSUPP => return errnoBug(err), // Bad flags with MAP.SHARED_VALIDATE on Linux.
                else => return posix.unexpectedErrno(err),
            }
        };
        return .{
            .file = file,
            .offset = offset,
            .memory = contents,
            .section = {},
        };
    }

    return error.OperationUnsupported;
}

fn fileMemoryMapDestroy(userdata: ?*anyopaque, mm: *File.MemoryMap) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const memory = mm.memory;
    if (mm.section) |section| switch (native_os) {
        .windows => {
            if (section == windows.INVALID_HANDLE_VALUE) return;
            _ = windows.ntdll.NtUnmapViewOfSection(windows.current_process, memory.ptr);
            windows.CloseHandle(section);
        },
        .wasi => unreachable,
        else => {
            if (memory.len == 0) return;
            switch (posix.errno(posix.system.munmap(memory.ptr, memory.len))) {
                .SUCCESS => {},
                else => |e| {
                    if (builtin.mode == .debug)
                        std.log.err("failed to unmap {d} bytes at {*}: {t}", .{ memory.len, memory.ptr, e });
                },
            }
        },
    } else {
        const gpa = t.allocator;
        gpa.rawFree(memory, .fromByteUnits(std.heap.pageSize()), @returnAddress());
    }
    mm.* = undefined;
}

fn fileMemoryMapSetLength(
    userdata: ?*anyopaque,
    mm: *File.MemoryMap,
    new_len: usize,
) File.MemoryMap.SetLengthError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const page_size = std.heap.pageSize();
    const alignment: Alignment = .fromByteUnits(page_size);
    const page_align = std.heap.page_size_min;
    const old_memory = mm.memory;

    if (mm.section) |section| {
        _ = section;
        if (alignment.forward(new_len) == alignment.forward(old_memory.len)) {
            mm.memory.len = new_len;
            return;
        }
        switch (native_os) {
            .wasi => unreachable,
            .linux => {
                const flags: posix.MREMAP = .{ .MAYMOVE = true };
                const addr_hint: ?[*]const u8 = null;
                const new_memory = while (true) {
                    const syscall: Syscall = try .start();
                    const rc = posix.system.mremap(old_memory.ptr, old_memory.len, new_len, flags, addr_hint);
                    syscall.finish();
                    const err: posix.E = if (builtin.link_libc) e: {
                        if (rc != std.c.MAP_FAILED) break @as([*]align(page_align) u8, @ptrCast(@alignCast(rc)))[0..new_len];
                        break :e @fromBackingInt(@intCast(posix.system._errno().*));
                    } else e: {
                        const err = posix.errno(rc);
                        if (err == .SUCCESS) break @as([*]align(page_align) u8, @ptrFromInt(rc))[0..new_len];
                        break :e err;
                    };
                    switch (err) {
                        .SUCCESS => unreachable,
                        .INTR => continue,
                        .AGAIN => return error.LockedMemoryLimitExceeded,
                        .NOMEM => return error.OutOfMemory,
                        .INVAL => return errnoBug(err),
                        .FAULT => return errnoBug(err),
                        else => return posix.unexpectedErrno(err),
                    }
                };
                mm.memory = new_memory;
                return;
            },
            else => return error.OperationUnsupported,
        }
    } else {
        const gpa = t.allocator;
        if (gpa.rawRemap(old_memory, alignment, new_len, @returnAddress())) |new_ptr| {
            mm.memory = @alignCast(new_ptr[0..new_len]);
        } else {
            const new_ptr: [*]align(page_align) u8 = @alignCast(
                gpa.rawAlloc(new_len, alignment, @returnAddress()) orelse return error.OutOfMemory,
            );
            const copy_len = @min(new_len, old_memory.len);
            @memcpy(new_ptr[0..copy_len], old_memory[0..copy_len]);
            mm.memory = new_ptr[0..new_len];
            gpa.rawFree(old_memory, alignment, @returnAddress());
        }
    }
}

fn fileMemoryMapRead(userdata: ?*anyopaque, mm: *File.MemoryMap) File.ReadPositionalError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const section = mm.section orelse return mmSyncRead(mm.file, mm.memory, mm.offset);
    _ = section;
}

fn fileMemoryMapWrite(userdata: ?*anyopaque, mm: *File.MemoryMap) File.WritePositionalError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const section = mm.section orelse return mmSyncWrite(mm.file, mm.memory, mm.offset);
    _ = section;
}

fn mmSyncRead(file: File, memory: []u8, offset: u64) File.ReadPositionalError!void {
    if (is_windows) {
        var i: usize = 0;
        while (true) {
            const buf = memory[i..];
            if (buf.len == 0) break;
            const n = try windows_impl.readFilePositionalWindows(file, buf, offset + i);
            if (n == 0) {
                @memset(memory[i..], 0);
                break;
            }
            i += n;
        }
    } else if (native_os == .wasi and !builtin.link_libc) {
        var i: usize = 0;
        const syscall: Syscall = try .start();
        while (true) {
            const buf = memory[i..];
            if (buf.len == 0) {
                syscall.finish();
                break;
            }
            var n: usize = undefined;
            const vec: std.os.wasi.iovec_t = .{ .base = buf.ptr, .len = buf.len };
            switch (std.os.wasi.fd_pread(file.handle, (&vec)[0..1], 1, offset + i, &n)) {
                .SUCCESS => {
                    if (n == 0) {
                        syscall.finish();
                        @memset(memory[i..], 0);
                        break;
                    }
                    i += n;
                    try syscall.checkCancel();
                    continue;
                },
                .INTR, .TIMEDOUT => {
                    try syscall.checkCancel();
                    continue;
                },
                .NOTCONN => |err| return syscall.errnoBug(err), // not a socket
                .CONNRESET => |err| return syscall.errnoBug(err), // not a socket
                .BADF => |err| return syscall.errnoBug(err), // use after free
                .INVAL => |err| return syscall.errnoBug(err),
                .FAULT => |err| return syscall.errnoBug(err), // segmentation fault
                .AGAIN => |err| return syscall.errnoBug(err),
                .IO => return syscall.fail(error.InputOutput),
                .ISDIR => return syscall.fail(error.IsDir),
                .NOBUFS => return syscall.fail(error.SystemResources),
                .NOMEM => return syscall.fail(error.SystemResources),
                .NXIO => return syscall.fail(error.Unseekable),
                .SPIPE => return syscall.fail(error.Unseekable),
                .OVERFLOW => return syscall.fail(error.Unseekable),
                .NOTCAPABLE => return syscall.fail(error.AccessDenied),
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    } else {
        var i: usize = 0;
        const syscall: Syscall = try .start();
        while (true) {
            const buf = memory[i..];
            if (buf.len == 0) {
                syscall.finish();
                break;
            }
            const rc = pread_sym(file.handle, buf.ptr, buf.len, @intCast(offset + i));
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) {
                        syscall.finish();
                        @memset(memory[i..], 0);
                        break;
                    }
                    i += n;
                    try syscall.checkCancel();
                    continue;
                },
                .INTR, .TIMEDOUT => {
                    try syscall.checkCancel();
                    continue;
                },
                .NXIO => return syscall.fail(error.Unseekable),
                .SPIPE => return syscall.fail(error.Unseekable),
                .OVERFLOW => return syscall.fail(error.Unseekable),
                .NOBUFS => return syscall.fail(error.SystemResources),
                .NOMEM => return syscall.fail(error.SystemResources),
                .AGAIN => return syscall.fail(error.WouldBlock),
                .IO => return syscall.fail(error.InputOutput),
                .ISDIR => return syscall.fail(error.IsDir),
                .NOTCONN => |err| return syscall.errnoBug(err), // not a socket
                .CONNRESET => |err| return syscall.errnoBug(err), // not a socket
                .INVAL => |err| return syscall.errnoBug(err),
                .FAULT => |err| return syscall.errnoBug(err),
                .BADF => |err| return syscall.errnoBug(err), // use after free
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    }
}

fn mmSyncWrite(file: File, memory: []u8, offset: u64) File.WritePositionalError!void {
    if (is_windows) {
        var i: usize = 0;
        while (true) {
            const buf = memory[i..];
            if (buf.len == 0) break;
            i += try windows_impl.writeFilePositionalWindows(file, memory[i..], offset + i);
        }
    } else if (native_os == .wasi and !builtin.link_libc) {
        var i: usize = 0;
        var n: usize = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            const buf = memory[i..];
            if (buf.len == 0) {
                syscall.finish();
                break;
            }
            const iovec: std.os.wasi.ciovec_t = .{ .base = buf.ptr, .len = buf.len };
            switch (std.os.wasi.fd_pwrite(file.handle, (&iovec)[0..1], 1, offset + i, &n)) {
                .SUCCESS => {
                    i += n;
                    try syscall.checkCancel();
                    continue;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                .DQUOT => return syscall.fail(error.DiskQuota),
                .FBIG => return syscall.fail(error.FileTooBig),
                .IO => return syscall.fail(error.InputOutput),
                .NOSPC => return syscall.fail(error.NoSpaceLeft),
                .PERM => return syscall.fail(error.PermissionDenied),
                .PIPE => return syscall.fail(error.BrokenPipe),
                .NOTCAPABLE => return syscall.fail(error.AccessDenied),
                .NXIO => return syscall.fail(error.Unseekable),
                .SPIPE => return syscall.fail(error.Unseekable),
                .OVERFLOW => return syscall.fail(error.Unseekable),
                .INVAL => |err| return syscall.errnoBug(err),
                .FAULT => |err| return syscall.errnoBug(err),
                .AGAIN => |err| return syscall.errnoBug(err),
                .BADF => |err| return syscall.errnoBug(err), // use after free
                .DESTADDRREQ => |err| return syscall.errnoBug(err), // not a socket
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    } else {
        var i: usize = 0;
        const syscall: Syscall = try .start();
        while (true) {
            const buf = memory[i..];
            if (buf.len == 0) {
                syscall.finish();
                break;
            }
            const rc = pwrite_sym(file.handle, buf.ptr, buf.len, @intCast(offset + i));
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @bitCast(rc);
                    i += n;
                    try syscall.checkCancel();
                    continue;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                .INVAL => |err| return syscall.errnoBug(err),
                .FAULT => |err| return syscall.errnoBug(err),
                .DESTADDRREQ => |err| return syscall.errnoBug(err), // not a socket
                .CONNRESET => |err| return syscall.errnoBug(err), // not a socket
                .BADF => return syscall.fail(error.NotOpenForWriting),
                .AGAIN => return syscall.fail(error.WouldBlock),
                .DQUOT => return syscall.fail(error.DiskQuota),
                .FBIG => return syscall.fail(error.FileTooBig),
                .IO => return syscall.fail(error.InputOutput),
                .NOSPC => return syscall.fail(error.NoSpaceLeft),
                .PERM => return syscall.fail(error.PermissionDenied),
                .PIPE => return syscall.fail(error.BrokenPipe),
                .BUSY => return syscall.fail(error.DeviceBusy),
                .TXTBSY => return syscall.fail(error.FileBusy),
                .NXIO => return syscall.fail(error.Unseekable),
                .SPIPE => return syscall.fail(error.Unseekable),
                .OVERFLOW => return syscall.fail(error.Unseekable),
                else => |err| return syscall.unexpectedErrno(err),
            }
        }
    }
}

pub fn deviceIoControl(o: *const Io.Operation.DeviceIoControl) Io.Cancelable!Io.Operation.DeviceIoControl.Result {
    if (is_windows) {
        const NtControlFile = switch (o.code.DeviceType) {
            .FILE_SYSTEM, .NAMED_PIPE => &windows.ntdll.NtFsControlFile,
            else => &windows.ntdll.NtDeviceIoControlFile,
        };
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        if (o.file.flags.nonblocking) {
            var done: bool = false;
            switch (NtControlFile(
                o.file.handle,
                null, // event
                flagApc,
                &done, // APC context
                &iosb,
                o.code,
                if (o.in.len > 0) o.in.ptr else null,
                @intCast(o.in.len),
                if (o.out.len > 0) o.out.ptr else null,
                @intCast(o.out.len),
            )) {
                // We must wait for the APC routine.
                .PENDING, .SUCCESS => while (!done) {
                    // Once we get here we must not return from the function until the
                    // operation completes, thereby releasing reference to io_status_block.
                    const alertable_syscall = AlertableSyscall.start() catch |err| switch (err) {
                        error.Canceled => |e| {
                            var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
                            _ = windows.ntdll.NtCancelIoFileEx(o.file.handle, &iosb, &cancel_iosb);
                            while (!done) waitForApcOrAlert();
                            return e;
                        },
                    };
                    waitForApcOrAlert();
                    alertable_syscall.finish();
                },
                else => |status| iosb.u.Status = status,
            }
        } else {
            const syscall: Syscall = try .start();
            while (true) switch (NtControlFile(
                o.file.handle,
                null, // event
                null, // APC routine
                null, // APC context
                &iosb,
                o.code,
                if (o.in.len > 0) o.in.ptr else null,
                @intCast(o.in.len),
                if (o.out.len > 0) o.out.ptr else null,
                @intCast(o.out.len),
            )) {
                .PENDING => unreachable, // unrecoverable: wrong asynchronous flag
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |status| {
                    syscall.finish();
                    iosb.u.Status = status;
                    break;
                },
            };
        }
        return iosb;
    } else {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = posix.system.ioctl(o.file.handle, @bitCast(o.code), @intFromPtr(o.arg));
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    if (@TypeOf(rc) == usize) return @bitCast(@as(u32, @truncate(rc)));
                    return rc;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |err| {
                    syscall.finish();
                    return -@as(i32, @backingInt(err));
                },
            }
        }
    }
}

const WaitGroup = struct {
    state: std.atomic.Value(usize),
    event: Io.Event,

    const init: WaitGroup = .{ .state = .{ .raw = 0 }, .event = .unset };

    const is_waiting: usize = 1 << 0;
    const one_pending: usize = 1 << 1;

    pub fn start(wg: *WaitGroup) void {
        const prev_state = wg.state.fetchAdd(one_pending, .monotonic);
        assert((prev_state / one_pending) < (std.math.maxInt(usize) / one_pending));
    }

    fn value(wg: *WaitGroup) usize {
        return wg.state.load(.monotonic) / one_pending;
    }

    fn wait(wg: *WaitGroup) void {
        const prev_state = wg.state.fetchAdd(is_waiting, .acquire);
        assert(prev_state & is_waiting == 0);
        if ((prev_state / one_pending) > 0) eventWait(&wg.event);
    }

    pub fn finish(wg: *WaitGroup) void {
        const state = wg.state.fetchSub(one_pending, .acq_rel);
        assert((state / one_pending) > 0);

        if (state == (one_pending | is_waiting)) {
            eventSet(&wg.event);
        }
    }
};

/// Same as `Io.Event.wait` but avoids the VTable.
fn eventWait(event: *Io.Event) void {
    if (@cmpxchgStrong(Io.Event, event, .unset, .waiting, .acquire, .acquire)) |prev| switch (prev) {
        .unset => unreachable,
        .waiting => {},
        .is_set => return,
    };
    while (true) {
        Thread.futexWaitUncancelable(@ptrCast(event), @backingInt(Io.Event.waiting), null);
        switch (@atomicLoad(Io.Event, event, .acquire)) {
            .unset => unreachable, // `reset` called before pending `wait` returned
            .waiting => continue,
            .is_set => return,
        }
    }
}

/// Same as `Io.Event.set` but avoids the VTable.
fn eventSet(event: *Io.Event) void {
    switch (@atomicRmw(Io.Event, event, .Xchg, .is_set, .release)) {
        .unset, .is_set => {},
        .waiting => Thread.futexWake(@ptrCast(event), std.math.maxInt(u32)),
    }
}

/// Same as `Io.Condition.broadcast` but avoids the VTable.
fn condBroadcast(cond: *Io.Condition) void {
    var prev_state = cond.state.load(.monotonic);
    while (prev_state.waiters > prev_state.signals) {
        @branchHint(.unlikely);
        prev_state = cond.state.cmpxchgWeak(prev_state, .{
            .waiters = prev_state.waiters,
            .signals = prev_state.waiters,
        }, .release, .monotonic) orelse {
            // Update the epoch to tell the waiting threads that there are new signals for them.
            // Note that a waiting thread could miss a take if *exactly* (1<<32)-1 wakes happen
            // between it observing the epoch and sleeping on it, but this is extraordinarily
            // unlikely due to the precise number of calls required.
            _ = cond.epoch.fetchAdd(1, .release); // `.release` to ensure ordered after `state` update
            Thread.futexWake(&cond.epoch.raw, prev_state.waiters - prev_state.signals);
            return;
        };
    }
}

/// Same as `Io.Condition.signal` but avoids the VTable.
fn condSignal(cond: *Io.Condition) void {
    var prev_state = cond.state.load(.monotonic);
    while (prev_state.waiters > prev_state.signals) {
        @branchHint(.unlikely);
        prev_state = cond.state.cmpxchgWeak(prev_state, .{
            .waiters = prev_state.waiters,
            .signals = prev_state.signals + 1,
        }, .release, .monotonic) orelse {
            // Update the epoch to tell the waiting threads that there are new signals for them.
            // Note that a waiting thread could miss a take if *exactly* (1<<32)-1 wakes happen
            // between it observing the epoch and sleeping on it, but this is extraordinarily
            // unlikely due to the precise number of calls required.
            _ = cond.epoch.fetchAdd(1, .release); // `.release` to ensure ordered after `state` update
            Thread.futexWake(&cond.epoch.raw, 1);
            return;
        };
    }
}

/// Same as `Io.Condition.waitUncancelable` but avoids the VTable.
fn condWait(cond: *Io.Condition, mutex: *Io.Mutex) void {
    var epoch = cond.epoch.load(.acquire); // `.acquire` to ensure ordered before state load

    {
        const prev_state = cond.state.fetchAdd(.{ .waiters = 1, .signals = 0 }, .monotonic);
        assert(prev_state.waiters < std.math.maxInt(u16)); // overflow caused by too many waiters
    }

    mutexUnlock(mutex);
    defer mutexLockUncancelable(mutex);

    while (true) {
        Thread.futexWaitUncancelable(&cond.epoch.raw, epoch, null);

        epoch = cond.epoch.load(.acquire); // `.acquire` to ensure ordered before `state` laod

        var prev_state = cond.state.load(.monotonic);
        while (prev_state.signals > 0) {
            prev_state = cond.state.cmpxchgWeak(prev_state, .{
                .waiters = prev_state.waiters - 1,
                .signals = prev_state.signals - 1,
            }, .acquire, .monotonic) orelse {
                // We successfully consumed a signal.
                return;
            };
        }
    }
}

/// Same as `Io.Mutex.lock` but avoids the VTable.
pub fn mutexLock(m: *Io.Mutex) Io.Cancelable!void {
    const initial_state = m.state.cmpxchgStrong(
        .unlocked,
        .locked_once,
        .acquire,
        .monotonic,
    ) orelse {
        @branchHint(.likely);
        return;
    };
    if (initial_state == .contended) {
        try Thread.futexWait(@ptrCast(&m.state.raw), @backingInt(Io.Mutex.State.contended), null);
    }
    while (m.state.swap(.contended, .acquire) != .unlocked) {
        try Thread.futexWait(@ptrCast(&m.state.raw), @backingInt(Io.Mutex.State.contended), null);
    }
}

/// Same as `Io.Mutex.lockUncancelable` but avoids the VTable.
pub fn mutexLockUncancelable(m: *Io.Mutex) void {
    const initial_state = m.state.cmpxchgStrong(
        .unlocked,
        .locked_once,
        .acquire,
        .monotonic,
    ) orelse {
        @branchHint(.likely);
        return;
    };
    if (initial_state == .contended) {
        Thread.futexWaitUncancelable(@ptrCast(&m.state.raw), @backingInt(Io.Mutex.State.contended), null);
    }
    while (m.state.swap(.contended, .acquire) != .unlocked) {
        Thread.futexWaitUncancelable(@ptrCast(&m.state.raw), @backingInt(Io.Mutex.State.contended), null);
    }
}

/// Same as `Io.Mutex.unlock` but avoids the VTable.
pub fn mutexUnlock(m: *Io.Mutex) void {
    switch (m.state.swap(.unlocked, .release)) {
        .unlocked => unreachable,
        .locked_once => {},
        .contended => {
            @branchHint(.unlikely);
            Thread.futexWake(@ptrCast(&m.state.raw), 1);
        },
    }
}

const OpenError = error{
    IsDir,
    NotDir,
    FileNotFound,
    NoDevice,
    AccessDenied,
    PipeBusy,
    PathAlreadyExists,
    WouldBlock,
    NetworkNotFound,
    AntivirusInterference,
    FileBusy,
} || Dir.PathNameError || Io.Cancelable || Io.UnexpectedError;

const OpenFileOptions = struct {
    access_mask: windows.ACCESS_MASK,
    dir: ?windows.HANDLE = null,
    sa: ?*const windows.SECURITY_ATTRIBUTES = null,
    share_access: windows.FILE.SHARE = .VALID_FLAGS,
    creation: windows.FILE.CREATE_DISPOSITION,
    filter: Filter = .non_directory_only,
    /// If false, tries to open path as a reparse point without dereferencing it.
    /// Defaults to true.
    follow_symlinks: bool = true,

    pub const Filter = enum {
        /// Causes `OpenFile` to return `error.IsDir` if the opened handle would be a directory.
        non_directory_only,
        /// Causes `OpenFile` to return `error.NotDir` if the opened handle is not a directory.
        dir_only,
        /// `OpenFile` does not discriminate between opening files and directories.
        any,
    };
};

/// TODO: inline this logic everywhere and delete this function
pub fn OpenFile(sub_path_w: []const u16, options: OpenFileOptions) OpenError!windows.HANDLE {
    if (std.mem.eql(u16, sub_path_w, &.{'.'}) and options.filter == .non_directory_only) {
        return error.IsDir;
    }
    if (std.mem.eql(u16, sub_path_w, &.{ '.', '.' }) and options.filter == .non_directory_only) {
        return error.IsDir;
    }

    var result: windows.HANDLE = undefined;

    const attr: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w)) null else options.dir,
        .Attributes = .{ .INHERIT = if (options.sa) |sa| sa.bInheritHandle.toBool() else false },
        .ObjectName = @constCast(&windows.UNICODE_STRING.init(sub_path_w)),
        .SecurityDescriptor = if (options.sa) |ptr| ptr.lpSecurityDescriptor else null,
    };

    var iosb: windows.IO_STATUS_BLOCK = undefined;
    var attempt: u5 = 0;
    var syscall: Syscall = try .start();
    while (true) {
        switch (windows.ntdll.NtCreateFile(
            &result,
            options.access_mask,
            &attr,
            &iosb,
            null,
            .{ .NORMAL = true },
            options.share_access,
            options.creation,
            .{
                .DIRECTORY_FILE = options.filter == .dir_only,
                .NON_DIRECTORY_FILE = options.filter == .non_directory_only,
                .IO = .SYNCHRONOUS_NONALERT,
                .OPEN_REPARSE_POINT = !options.follow_symlinks,
            },
            null,
            0,
        )) {
            .SUCCESS => {
                syscall.finish();
                return result;
            },
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .SHARING_VIOLATION => {
                // This occurs if the file attempting to be opened is a running
                // executable. However, there's a kernel bug: the error may be
                // incorrectly returned for an indeterminate amount of time
                // after an executable file is closed. Here we work around the
                // kernel bug with retry attempts.
                syscall.finish();
                if (windows_impl.max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
                try parking_sleep.sleep(.{ .duration = .{
                    .raw = .fromMilliseconds((@as(u32, 1) << attempt) >> 1),
                    .clock = .awake,
                } });
                attempt += 1;
                syscall = try .start();
                continue;
            },
            .DELETE_PENDING => {
                // This error means that there *was* a file in this location on
                // the file system, but it was deleted. However, the OS is not
                // finished with the deletion operation, and so this CreateFile
                // call has failed. There is not really a sane way to handle
                // this other than retrying the creation after the OS finishes
                // the deletion.
                syscall.finish();
                if (windows_impl.max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
                try parking_sleep.sleep(.{ .duration = .{
                    .raw = .fromMilliseconds((@as(u32, 1) << attempt) >> 1),
                    .clock = .awake,
                } });
                attempt += 1;
                syscall = try .start();
                continue;
            },
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .BAD_NETWORK_PATH => return syscall.fail(error.NetworkNotFound), // \\server was not found
            .BAD_NETWORK_NAME => return syscall.fail(error.NetworkNotFound), // \\server was found but \\server\share wasn't
            .NO_MEDIA_IN_DEVICE => return syscall.fail(error.NoDevice),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .PIPE_BUSY => return syscall.fail(error.PipeBusy),
            .PIPE_NOT_AVAILABLE => return syscall.fail(error.NoDevice),
            .OBJECT_NAME_COLLISION => return syscall.fail(error.PathAlreadyExists),
            .FILE_IS_A_DIRECTORY => return syscall.fail(error.IsDir),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
            .VIRUS_INFECTED, .VIRUS_DELETED => return syscall.fail(error.AntivirusInterference),
            .INVALID_PARAMETER => |status| return syscall.ntstatusBug(status),
            .OBJECT_PATH_SYNTAX_BAD => |status| return syscall.ntstatusBug(status),
            .INVALID_HANDLE => |status| return syscall.ntstatusBug(status),
            else => |status| return syscall.unexpectedNtstatus(status),
        }
    }
}

pub fn closeFd(fd: posix.fd_t) void {
    if (native_os == .wasi and !builtin.link_libc) {
        switch (std.os.wasi.fd_close(fd)) {
            .SUCCESS, .INTR => {},
            .BADF => recoverableOsBugDetected(), // use after free
            else => recoverableOsBugDetected(), // unexpected failure
        }
    } else switch (posix.errno(posix.system.close(fd))) {
        .SUCCESS, .INTR => {}, // INTR still a success, see https://github.com/ziglang/zig/issues/2425
        .BADF => recoverableOsBugDetected(), // use after free
        else => recoverableOsBugDetected(), // unexpected failure
    }
}
