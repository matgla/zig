//! The darwin part of `std.Io.Threaded`, in its own file so that a compiler
//! building for another system never loads it.

const Threaded = @import("../Threaded.zig");
const Dir = Threaded.Dir;
const File = Threaded.File;
const Spawned = Threaded.Spawned;
const Syscall = Threaded.Syscall;
const builtin = Threaded.builtin;
const closeFd = Threaded.closeFd;
const default_PATH = Threaded.default_PATH;
const destroyPipe = Threaded.destroyPipe;
const errnoBug = Threaded.errnoBug;
const pathToPosix = Threaded.pathToPosix;
const pipe2 = Threaded.pipe2;
const posix = Threaded.posix;
const posixSeekTo = Threaded.posixSeekTo;
const process = Threaded.process;
const realPathPosix = Threaded.realPathPosix;
const recoverableOsBugDetected = Threaded.recoverableOsBugDetected;
const std = Threaded.std;

pub fn dirReadDarwin(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const Header = extern struct {
        seek: i64,
    };
    const header: *Header = @ptrCast(dr.buffer.ptr);
    const header_end: usize = @sizeOf(Header);
    if (dr.index < header_end) {
        // Initialize header.
        dr.index = header_end;
        dr.end = header_end;
        header.* = .{ .seek = 0 };
    }
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
            const dents_buffer = dr.buffer[header_end..];
            const syscall: Syscall = try .start();
            const n: usize = while (true) {
                const rc = posix.system.getdirentries(dr.dir.handle, dents_buffer.ptr, dents_buffer.len, &header.seek);
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
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability.
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
            dr.index = header_end;
            dr.end = header_end + n;
        }
        const darwin_entry = @as(*align(1) posix.system.dirent, @ptrCast(&dr.buffer[dr.index]));
        const next_index = dr.index + darwin_entry.reclen;
        dr.index = next_index;

        const name = @as([*]u8, @ptrCast(&darwin_entry.name))[0..darwin_entry.namlen];
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or (darwin_entry.ino == 0))
            continue;

        const entry_kind: File.Kind = switch (darwin_entry.type) {
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
            .inode = darwin_entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

pub fn dirRenamePreserveDarwin(
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenamePreserveError!void {
    var old_path_buffer: [posix.PATH_MAX]u8 = undefined;
    var new_path_buffer: [posix.PATH_MAX]u8 = undefined;
    const old_sub_path_posix = try pathToPosix(old_sub_path, &old_path_buffer);
    const new_sub_path_posix = try pathToPosix(new_sub_path, &new_path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(std.c.renameatx_np(
            old_dir.handle,
            old_sub_path_posix,
            new_dir.handle,
            new_sub_path_posix,
            .{ .EXCL = true },
        ))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .INVAL => |err| return syscall.errnoBug(err),
            .FAULT => |err| return syscall.errnoBug(err),
            .BADF => |err| return syscall.errnoBug(err),
            .ISDIR => |err| return syscall.errnoBug(err),
            .NOTEMPTY => |err| return syscall.errnoBug(err),
            .OPNOTSUPP => return syscall.fail(error.OperationUnsupported),
            .IO => return syscall.fail(error.HardwareFailure),
            .DEADLK => return syscall.fail(error.AccessDenied),
            .ACCES => return syscall.fail(error.AccessDenied),
            .DQUOT => return syscall.fail(error.DiskQuota),
            .EXIST => return syscall.fail(error.PathAlreadyExists),
            .LOOP => return syscall.fail(error.LinkQuotaExceeded),
            .NAMETOOLONG => return syscall.fail(error.NameTooLong),
            .NOENT => return syscall.fail(error.FileNotFound),
            .NOSPC => return syscall.fail(error.NoSpaceLeft),
            .NOTDIR => return syscall.fail(error.NotDir),
            .PERM => return syscall.fail(error.PermissionDenied),
            .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
            .XDEV => return syscall.fail(error.CrossDevice),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

/// Darwin XNU 7195.50.7.100.1 introduced __ulock_wait2 and migrated code paths (notably pthread_cond_t) towards it:
/// https://github.com/apple/darwin-xnu/commit/d4061fb0260b3ed486147341b72468f836ed6c8f#diff-08f993cc40af475663274687b7c326cc6c3031e0db3ac8de7b24624610616be6
///
/// This XNU version appears to correspond to 11.0.1:
/// https://kernelshaman.blogspot.com/2021/01/building-xnu-for-macos-big-sur-1101.html
///
/// ulock_wait() uses 32-bit micro-second timeouts where 0 = INFINITE or no-timeout
/// ulock_wait2() uses 64-bit nano-second timeouts (with the same convention)
pub const darwin_supports_ulock_wait2 = builtin.os.version_range.semver.min.major >= 11;

pub fn processSpawnDarwin(userdata: ?*anyopaque, options: process.SpawnOptions) process.SpawnError!process.Child {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

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

    const spawned = try spawnDarwin(t, 
        .spawn,
        options.exe,
        argv_buf.ptr,
        options.cwd,
        env_block,
        options.expand_arg0,
        options.progress_node,
        options.stdin,
        options.stdout,
        options.stderr,
        options.inherit_dirs,
        options.inherit_files,
        options.pgid,
        options.start_suspended,
        PATH,
    );
    return .{
        .id = spawned.pid,
        .thread_handle = {},
        .stdin = spawned.stdin,
        .stdout = spawned.stdout,
        .stderr = spawned.stderr,
        .request_resource_usage_statistics = options.request_resource_usage_statistics,
    };
}

pub fn spawnDarwin(
    t: *Threaded,
    mode: enum { spawn, replace },
    exe: process.ReplaceOptions.Exe,
    argv: [*:null]?[*:0]const u8,
    cwd: process.Child.Cwd,
    env_block: process.Environ.PosixBlock,
    expand_arg0: process.ArgExpansion,
    progress_node: std.Progress.Node,
    stdin: process.SpawnOptions.StdIo,
    stdout: process.SpawnOptions.StdIo,
    stderr: process.SpawnOptions.StdIo,
    inherit_dirs: []const Dir,
    inherit_files: []const File,
    pgid: ?posix.pid_t,
    start_suspended: bool,
    PATH: []const u8,
) (process.SpawnError || process.ReplaceError)!Spawned {
    var fa: std.c.posix_spawn_file_actions_t = undefined;
    switch (@as(std.c.E, @fromBackingInt(@intCast(std.c.posix_spawn_file_actions_init(&fa))))) {
        .SUCCESS => {},
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
    defer switch (@as(std.c.E, @fromBackingInt(@intCast(
        std.c.posix_spawn_file_actions_destroy(&fa),
    )))) {
        .SUCCESS => {},
        .INVAL => recoverableOsBugDetected(),
        else => recoverableOsBugDetected(),
    };

    var attr: std.c.posix_spawnattr_t = undefined;
    switch (@as(std.c.E, @fromBackingInt(@intCast(std.c.posix_spawnattr_init(&attr))))) {
        .SUCCESS => {},
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
    defer switch (@as(std.c.E, @fromBackingInt(@intCast(std.c.posix_spawnattr_destroy(&attr))))) {
        .SUCCESS => {},
        .INVAL => recoverableOsBugDetected(),
        else => recoverableOsBugDetected(),
    };

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

    const stdin_pipe = if (stdin == .pipe) try pipe2(pipe_flags) else undefined;
    errdefer if (stdin == .pipe) {
        destroyPipe(stdin_pipe);
    };

    const stdout_pipe = if (stdout == .pipe) try pipe2(pipe_flags) else undefined;
    errdefer if (stdout == .pipe) {
        destroyPipe(stdout_pipe);
    };

    const stderr_pipe = if (stderr == .pipe) try pipe2(pipe_flags) else undefined;
    errdefer if (stderr == .pipe) {
        destroyPipe(stderr_pipe);
    };

    const any_ignore = (stdin == .ignore or stdout == .ignore or stderr == .ignore);
    const dev_null_fd = if (any_ignore) try t.getDevNullFd() else undefined;

    const prog_pipe: [2]posix.fd_t = if (progress_node.index != .none) pipe: {
        // We use CLOEXEC for the same reason as in `pipe_flags`.
        break :pipe try pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    } else .{ -1, -1 };
    errdefer destroyPipe(prog_pipe);

    var cwd_buffer: [posix.PATH_MAX]u8 = undefined;
    switch (cwd) {
        .inherit => {},
        .dir => |dir| switch (@as(std.c.E, @fromBackingInt(@intCast(
            std.c.posix_spawn_file_actions_addfchdir_np(&fa, dir.handle),
        )))) {
            .SUCCESS => {},
            .BADF => |err| return errnoBug(err),
            .INVAL => |err| return errnoBug(err),
            .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        },
        .path => |path| switch (@as(std.c.E, @fromBackingInt(@intCast(
            std.c.posix_spawn_file_actions_addchdir_np(&fa, try pathToPosix(path, &cwd_buffer)),
        )))) {
            .SUCCESS => {},
            .BADF => |err| return errnoBug(err),
            .INVAL => |err| return errnoBug(err),
            .NAMETOOLONG => return error.NameTooLong,
            .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        },
    }

    for (inherit_dirs) |inherit_dir| switch (@as(std.c.E, @fromBackingInt(@intCast(
        std.c.posix_spawn_file_actions_addinherit_np(&fa, inherit_dir.handle),
    )))) {
        .SUCCESS => {},
        .BADF => |err| return errnoBug(err),
        .INVAL => |err| return errnoBug(err),
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    };
    for (inherit_files) |inherit_file| switch (@as(std.c.E, @fromBackingInt(@intCast(
        std.c.posix_spawn_file_actions_addinherit_np(&fa, inherit_file.handle),
    )))) {
        .SUCCESS => {},
        .BADF => |err| return errnoBug(err),
        .INVAL => |err| return errnoBug(err),
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    };
    if (prog_pipe[1] != -1) switch (@as(std.c.E, @fromBackingInt(@intCast(
        std.c.posix_spawn_file_actions_addinherit_np(&fa, prog_pipe[1]),
    )))) {
        .SUCCESS => {},
        .BADF => |err| return errnoBug(err),
        .INVAL => |err| return errnoBug(err),
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    };
    for (
        [_]process.SpawnOptions.StdIo{ stdin, stdout, stderr },
        [_]posix.fd_t{ stdin_pipe[0], stdout_pipe[1], stderr_pipe[1] },
        [_]posix.fd_t{ posix.STDIN_FILENO, posix.STDOUT_FILENO, posix.STDERR_FILENO },
    ) |stdio, pipe_fd, std_fd| switch (@as(std.c.E, @fromBackingInt(@intCast(switch (stdio) {
        .pipe => std.c.posix_spawn_file_actions_adddup2(&fa, pipe_fd, std_fd),
        .close => std.c.posix_spawn_file_actions_addclose(&fa, std_fd),
        .inherit => std.c.posix_spawn_file_actions_addinherit_np(&fa, std_fd),
        .ignore => std.c.posix_spawn_file_actions_adddup2(&fa, dev_null_fd, std_fd),
        .file => |file| std.c.posix_spawn_file_actions_adddup2(&fa, file.handle, std_fd),
    })))) {
        .SUCCESS => {},
        .BADF => |err| return errnoBug(err),
        .INVAL => |err| return errnoBug(err),
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    };

    if (pgid) |pid| switch (@as(std.c.E, @fromBackingInt(@intCast(
        std.c.posix_spawnattr_setpgroup(&attr, pid),
    )))) {
        .SUCCESS => {},
        .INVAL => return error.InvalidProcessGroupId,
        else => |err| return posix.unexpectedErrno(err),
    };

    switch (@as(std.c.E, @fromBackingInt(@intCast(std.c.posix_spawnattr_setflags(&attr, .{
        .SETPGROUP = pgid != null,
        .SETEXEC = switch (mode) {
            .spawn => false,
            .replace => true,
        },
        .START_SUSPENDED = start_suspended,
    }))))) {
        .SUCCESS => {},
        .INVAL => |err| return errnoBug(err),
        else => |err| return posix.unexpectedErrno(err),
    }

    var pid: posix.pid_t = undefined;
    const arg0_slice = std.mem.span(argv[0].?);
    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    switch (err: {
        break :err @as(std.c.E, @fromBackingInt(@intCast(exe: switch (exe) {
            .detect => if (std.mem.findScalar(u8, arg0_slice, '/')) |_|
                std.c.posix_spawn(&pid, arg0_slice, &fa, &attr, argv, env_block.slice.ptr)
            else
                continue :exe .search,
            .search => if (!Dir.path.isAbsolute(arg0_slice)) {
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
                    switch (@as(std.c.E, @fromBackingInt(@intCast(
                        std.c.posix_spawn(&pid, full_path, &fa, &attr, argv, env_block.slice.ptr),
                    )))) {
                        else => |e| break :err e,
                        .ACCES, .NOENT, .NOTDIR => |e| switch (err) {
                            error.AccessDenied => {},
                            error.FileNotFound, error.NotDir => err = switch (e) {
                                else => unreachable,
                                .ACCES => error.AccessDenied,
                                .NOENT => error.FileNotFound,
                                .NOTDIR => error.NotDir,
                            },
                        },
                    }
                }
                return err;
            } else std.c.posix_spawn(&pid, arg0_slice, &fa, &attr, argv, env_block.slice.ptr),
            .path => |path| if (path.handle != posix.AT.FDCWD and !Dir.path.isAbsolute(arg0_slice)) {
                var path_len = realPathPosix(path.handle, &path_buffer) catch |err| switch (err) {
                    else => |e| return e,
                    error.InputOutput => return error.FileNotFound,
                };
                path_buffer[path_len] = Dir.path.sep;
                path_len += 1;
                @memcpy(path_buffer[path_len..][0..arg0_slice.len], arg0_slice);
                path_len += arg0_slice.len;
                path_buffer[path_len] = 0;
                break :exe std.c.posix_spawn(
                    &pid,
                    path_buffer[0..path_len :0],
                    &fa,
                    &attr,
                    argv,
                    env_block.slice.ptr,
                );
            } else std.c.posix_spawn(&pid, arg0_slice, &fa, &attr, argv, env_block.slice.ptr),
            .file => |file| {
                const path_len = realPathPosix(file.handle, &path_buffer) catch |err| switch (err) {
                    else => |e| return e,
                    error.InputOutput => return error.FileNotFound,
                };
                path_buffer[path_len] = 0;
                break :exe std.c.posix_spawn(
                    &pid,
                    path_buffer[0..path_len :0],
                    &fa,
                    &attr,
                    argv,
                    env_block.slice.ptr,
                );
            },
            .explicit => |explicit| if (explicit.dir.handle != posix.AT.FDCWD and
                !Dir.path.isAbsolute(explicit.path))
            {
                var path_len = realPathPosix(
                    explicit.dir.handle,
                    &path_buffer,
                ) catch |err| switch (err) {
                    else => |e| return e,
                    error.InputOutput => return error.FileNotFound,
                };
                path_buffer[path_len] = Dir.path.sep;
                path_len += 1;
                @memcpy(path_buffer[path_len..][0..explicit.path.len], explicit.path);
                path_len += explicit.path.len;
                path_buffer[path_len] = 0;
                break :exe std.c.posix_spawn(
                    &pid,
                    path_buffer[0..path_len :0],
                    &fa,
                    &attr,
                    argv,
                    env_block.slice.ptr,
                );
            } else std.c.posix_spawn(
                &pid,
                try pathToPosix(explicit.path, &path_buffer),
                &fa,
                &attr,
                argv,
                env_block.slice.ptr,
            ),
        })));
    }) {
        .SUCCESS => {},
        .AGAIN => return error.SystemResources,
        .INVAL => |err| return errnoBug(err),
        .@"2BIG" => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .FAULT => |err| return errnoBug(err),
        .IO => return error.FileSystem,
        .LOOP => return error.FileSystem,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOEXEC => return error.InvalidExe,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .TXTBSY => return error.FileBusy,
        .BADARCH => return error.InvalidExe,
        .BADF => |err| return errnoBug(err),
        else => |err| return posix.unexpectedErrno(err),
    }

    errdefer comptime unreachable; // The child is spawned; we must not error from now on

    if (stdin == .pipe) closeFd(stdin_pipe[0]);
    if (stdout == .pipe) closeFd(stdout_pipe[1]);
    if (stderr == .pipe) closeFd(stderr_pipe[1]);

    if (prog_pipe[1] != -1) closeFd(prog_pipe[1]);
    progress_node.setIpcFile(t, .{ .handle = prog_pipe[0], .flags = .{ .nonblocking = true } });

    return .{
        .pid = pid,
        .err_fd = -1,
        .stdin = switch (stdin) {
            .pipe => .{ .handle = stdin_pipe[1], .flags = .{ .nonblocking = false } },
            else => null,
        },
        .stdout = switch (stdout) {
            .pipe => .{ .handle = stdout_pipe[0], .flags = .{ .nonblocking = false } },
            else => null,
        },
        .stderr = switch (stderr) {
            .pipe => .{ .handle = stderr_pipe[0], .flags = .{ .nonblocking = false } },
            else => null,
        },
    };
}
