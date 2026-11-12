//! The windows part of `std.Io.Threaded`, in its own file so that a compiler
//! building for another system never loads it.

const Threaded = @import("../Threaded.zig");
const net_impl = Threaded.net_impl;
const AlertableSyscall = Threaded.AlertableSyscall;
const Allocator = Threaded.Allocator;
const ArgvToCommandLineError = Threaded.ArgvToCommandLineError;
const Csprng = Threaded.Csprng;
const Dir = Threaded.Dir;
const File = Threaded.File;
const HostName = Threaded.HostName;
const Io = Threaded.Io;
const IpAddress = Threaded.IpAddress;
const OpenFile = Threaded.OpenFile;
const PosixAddress = Threaded.PosixAddress;
const Syscall = Threaded.Syscall;
const Thread = Threaded.Thread;
const UnixAddress = Threaded.UnixAddress;
const Wtf8ToPrefixedFileWError = Threaded.Wtf8ToPrefixedFileWError;
const addressFromPosix = Threaded.addressFromPosix;
const addressToPosix = Threaded.addressToPosix;
const addressUnixToPosix = Threaded.addressUnixToPosix;
const apc_align = Threaded.apc_align;
const assert = Threaded.assert;
const builtin = Threaded.builtin;
const deinit = Threaded.deinit;
const deviceIoControl = Threaded.deviceIoControl;
const flagApc = Threaded.flagApc;
const have_networking = Threaded.have_networking;
const init = Threaded.init;
const max_iovecs_len = Threaded.max_iovecs_len;
const mutexLock = Threaded.mutexLock;
const mutexLockUncancelable = Threaded.mutexLockUncancelable;
const mutexUnlock = Threaded.mutexUnlock;
const native_os = Threaded.native_os;
const net = Threaded.net;
const parking_sleep = Threaded.parking_sleep;
const posixAddressFamily = Threaded.posixAddressFamily;
const posixSocketModeProtocol = Threaded.posixSocketModeProtocol;
const process = Threaded.process;
const std = Threaded.std;
const swapCancelProtection = Threaded.swapCancelProtection;
const waitForApcOrAlert = Threaded.waitForApcOrAlert;
const windows = Threaded.windows;
const windows_lock_range_len = Threaded.windows_lock_range_len;
const windows_lock_range_off = Threaded.windows_lock_range_off;
const ws2_32 = Threaded.ws2_32;

/// There are multiple kernel bugs being worked around with retries.
pub const max_windows_kernel_bug_retries = 13;

pub const WindowsBatchOperationUserdata = extern struct {
    file: windows.HANDLE,
    iosb: windows.IO_STATUS_BLOCK,

    const Erased = Io.Operation.Storage.Pending.Userdata;

    comptime {
        assert(@sizeOf(WindowsBatchOperationUserdata) <= @sizeOf(Erased));
    }

    fn toErased(userdata: *WindowsBatchOperationUserdata) *Erased {
        return @ptrCast(userdata);
    }

    pub fn fromErased(erased: *Erased) *WindowsBatchOperationUserdata {
        return @ptrCast(erased);
    }
};

pub fn batchCompleteBlockingWindows(
    b: *Io.Batch,
    operation_userdata: *WindowsBatchOperationUserdata,
    result: Io.Operation.Result,
) void {
    const erased_userdata = operation_userdata.toErased();
    const pending: *Io.Operation.Storage.Pending = @fieldParentPtr("userdata", erased_userdata);
    switch (pending.node.prev) {
        .none => b.pending.head = pending.node.next,
        else => |prev_index| b.storage[prev_index.toIndex()].pending.node.next = pending.node.next,
    }
    switch (pending.node.next) {
        .none => b.pending.tail = pending.node.prev,
        else => |next_index| b.storage[next_index.toIndex()].pending.node.prev = pending.node.prev,
    }
    const storage: *Io.Operation.Storage = @fieldParentPtr("pending", pending);
    const index: Io.Operation.OptionalIndex = .fromIndex(storage - b.storage.ptr);
    switch (b.completed.tail) {
        .none => b.completed.head = index,
        else => |tail_index| b.storage[tail_index.toIndex()].completion.node.next = index,
    }
    b.completed.tail = index;
    storage.* = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
}

pub fn batchApc(
    apc_context: ?*anyopaque,
    iosb: *windows.IO_STATUS_BLOCK,
    _: windows.ULONG,
) align(apc_align) callconv(.winapi) void {
    const b: *Io.Batch = @ptrCast(@alignCast(apc_context));
    const operation_userdata: *WindowsBatchOperationUserdata = @fieldParentPtr("iosb", iosb);
    const erased_userdata = operation_userdata.toErased();
    const pending: *Io.Operation.Storage.Pending = @fieldParentPtr("userdata", erased_userdata);
    switch (pending.node.prev) {
        .none => b.pending.head = pending.node.next,
        else => |prev_index| b.storage[prev_index.toIndex()].pending.node.next = pending.node.next,
    }
    switch (pending.node.next) {
        .none => b.pending.tail = pending.node.prev,
        else => |next_index| b.storage[next_index.toIndex()].pending.node.prev = pending.node.prev,
    }
    const storage: *Io.Operation.Storage = @fieldParentPtr("pending", pending);
    const index: Io.Operation.OptionalIndex = .fromIndex(storage - b.storage.ptr);
    switch (iosb.u.Status) {
        .CANCELLED => {
            const tail_index = b.unused.tail;
            switch (tail_index) {
                .none => b.unused.head = index,
                else => b.storage[tail_index.toIndex()].unused.next = index,
            }
            storage.* = .{ .unused = .{ .prev = tail_index, .next = .none } };
            b.unused.tail = index;
        },
        else => {
            switch (b.completed.tail) {
                .none => b.completed.head = index,
                else => |tail_index| b.storage[tail_index.toIndex()].completion.node.next = index,
            }
            b.completed.tail = index;
            const result: Io.Operation.Result = switch (pending.tag) {
                .file_read_streaming => .{ .file_read_streaming = ntReadFileResult(iosb) },
                .file_write_streaming => .{ .file_write_streaming = ntWriteFileResult(iosb) },
                .device_io_control => .{ .device_io_control = iosb.* },
                .net_receive => unreachable,
                .net_send => unreachable,
                .net_read => unreachable,
                .net_write => unreachable,
            };
            storage.* = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
        },
    }
}

/// If `concurrency` is false, `error.ConcurrencyUnavailable` is unreachable.
pub fn batchDrainSubmittedWindows(t: *Threaded, b: *Io.Batch, concurrency: bool) (Io.ConcurrentError || Io.Cancelable)!void {
    var index = b.submitted.head;
    errdefer b.submitted.head = index;
    while (index != .none) {
        const storage = &b.storage[index.toIndex()];
        const submission = storage.submission;
        storage.* = .{ .pending = .{
            .node = .{ .prev = b.pending.tail, .next = .none },
            .tag = submission.operation,
            .userdata = undefined,
        } };
        switch (b.pending.tail) {
            .none => b.pending.head = index,
            else => |tail_index| b.storage[tail_index.toIndex()].pending.node.next = index,
        }
        b.pending.tail = index;
        const operation_userdata: *WindowsBatchOperationUserdata = .fromErased(&storage.pending.userdata);
        errdefer {
            operation_userdata.iosb = .{ .u = .{ .Status = .CANCELLED }, .Information = undefined };
            batchApc(b, &operation_userdata.iosb, 0);
        }
        switch (submission.operation) {
            .file_read_streaming => |o| o: {
                var data_index: usize = 0;
                while (o.data.len - data_index != 0 and o.data[data_index].len == 0) data_index += 1;
                if (o.data.len - data_index == 0) {
                    operation_userdata.iosb = .{ .u = .{ .Status = .SUCCESS }, .Information = 0 };
                    batchApc(b, &operation_userdata.iosb, 0);
                    break :o;
                }
                const buffer = o.data[data_index];
                const short_buffer_len = std.math.lossyCast(u32, buffer.len);

                if (o.file.flags.nonblocking) {
                    operation_userdata.file = o.file.handle;
                    switch (windows.ntdll.NtReadFile(
                        o.file.handle,
                        null, // event
                        &batchApc,
                        b,
                        &operation_userdata.iosb,
                        buffer.ptr,
                        short_buffer_len,
                        null, // byte offset
                        null, // key
                    )) {
                        .PENDING, .SUCCESS => {},
                        .CANCELLED => unreachable,
                        else => |status| {
                            operation_userdata.iosb.u.Status = status;
                            batchApc(b, &operation_userdata.iosb, 0);
                        },
                    }
                } else {
                    if (concurrency) return error.ConcurrencyUnavailable;

                    const syscall: Syscall = try .start();
                    while (true) switch (windows.ntdll.NtReadFile(
                        o.file.handle,
                        null, // event
                        null, // APC routine
                        null, // APC context
                        &operation_userdata.iosb,
                        buffer.ptr,
                        short_buffer_len,
                        null, // byte offset
                        null, // key
                    )) {
                        .PENDING => unreachable, // unrecoverable: wrong File nonblocking flag
                        .CANCELLED => {
                            try syscall.checkCancel();
                            continue;
                        },
                        else => |status| {
                            syscall.finish();
                            operation_userdata.iosb.u.Status = status;
                            batchApc(b, &operation_userdata.iosb, 0);
                            break;
                        },
                    };
                }
            },
            .file_write_streaming => |o| o: {
                const buffer = windowsWriteBuffer(o.header, o.data, o.splat);
                if (buffer.len == 0) {
                    operation_userdata.iosb = .{ .u = .{ .Status = .SUCCESS }, .Information = 0 };
                    batchApc(b, &operation_userdata.iosb, 0);
                    break :o;
                }
                if (o.file.flags.nonblocking) {
                    operation_userdata.file = o.file.handle;
                    switch (windows.ntdll.NtWriteFile(
                        o.file.handle,
                        null, // event
                        &batchApc,
                        b,
                        &operation_userdata.iosb,
                        buffer.ptr,
                        @intCast(buffer.len),
                        null, // byte offset
                        null, // key
                    )) {
                        .PENDING, .SUCCESS => {},
                        .CANCELLED => unreachable,
                        else => |status| {
                            operation_userdata.iosb.u.Status = status;
                            batchApc(b, &operation_userdata.iosb, 0);
                        },
                    }
                } else {
                    if (concurrency) return error.ConcurrencyUnavailable;

                    const syscall: Syscall = try .start();
                    while (true) switch (windows.ntdll.NtWriteFile(
                        o.file.handle,
                        null, // event
                        null, // APC routine
                        null, // APC context
                        &operation_userdata.iosb,
                        buffer.ptr,
                        @intCast(buffer.len),
                        null, // byte offset
                        null, // key
                    )) {
                        .PENDING => unreachable, // unrecoverable: wrong File nonblocking flag
                        .CANCELLED => {
                            try syscall.checkCancel();
                            continue;
                        },
                        else => |status| {
                            syscall.finish();
                            operation_userdata.iosb.u.Status = status;
                            batchApc(b, &operation_userdata.iosb, 0);
                            break;
                        },
                    };
                }
            },
            .device_io_control => |o| {
                const NtControlFile = switch (o.code.DeviceType) {
                    .FILE_SYSTEM, .NAMED_PIPE => &windows.ntdll.NtFsControlFile,
                    else => &windows.ntdll.NtDeviceIoControlFile,
                };
                if (o.file.flags.nonblocking) {
                    operation_userdata.file = o.file.handle;
                    switch (NtControlFile(
                        o.file.handle,
                        null, // event
                        &batchApc,
                        b,
                        &operation_userdata.iosb,
                        o.code,
                        if (o.in.len > 0) o.in.ptr else null,
                        @intCast(o.in.len),
                        if (o.out.len > 0) o.out.ptr else null,
                        @intCast(o.out.len),
                    )) {
                        .PENDING, .SUCCESS => {},
                        .CANCELLED => unreachable,
                        else => |status| {
                            operation_userdata.iosb.u.Status = status;
                            batchApc(b, &operation_userdata.iosb, 0);
                        },
                    }
                } else {
                    if (concurrency) return error.ConcurrencyUnavailable;

                    const syscall: Syscall = try .start();
                    while (true) switch (NtControlFile(
                        o.file.handle,
                        null, // event
                        null, // APC routine
                        null, // APC context
                        &operation_userdata.iosb,
                        o.code,
                        if (o.in.len > 0) o.in.ptr else null,
                        @intCast(o.in.len),
                        if (o.out.len > 0) o.out.ptr else null,
                        @intCast(o.out.len),
                    )) {
                        .PENDING => unreachable, // unrecoverable: wrong File nonblocking flag
                        .CANCELLED => {
                            try syscall.checkCancel();
                            continue;
                        },
                        else => |status| {
                            syscall.finish();
                            operation_userdata.iosb.u.Status = status;
                            batchApc(b, &operation_userdata.iosb, 0);
                            break;
                        },
                    };
                }
            },
            .net_receive => |*o| {
                // TODO integrate with overlapped I/O or equivalent to avoid this error
                if (concurrency) return error.ConcurrencyUnavailable;
                batchCompleteBlockingWindows(b, operation_userdata, .{
                    .net_receive = netReceiveWindows(t, o.socket_handle, o.message_buffer, o.data_buffer, o.flags),
                });
            },
            .net_send => |*o| {
                // TODO integrate with overlapped I/O or equivalent to avoid this error
                if (concurrency) return error.ConcurrencyUnavailable;
                batchCompleteBlockingWindows(b, operation_userdata, .{
                    .net_send = netSendWindows(t, o.socket_handle, o.messages, o.flags),
                });
            },
            .net_read => |*o| {
                // TODO integrate with overlapped I/O or equivalent to avoid this error
                if (concurrency) return error.ConcurrencyUnavailable;
                batchCompleteBlockingWindows(b, operation_userdata, .{
                    .net_read = net_impl.netRead(o.socket_handle, o.data, o.control) catch |err| switch (err) {
                        error.Canceled => |e| return e,
                        else => |e| e,
                    },
                });
            },
            .net_write => |*o| {
                // TODO integrate with overlapped I/O or equivalent to avoid this error
                if (concurrency) return error.ConcurrencyUnavailable;
                batchCompleteBlockingWindows(b, operation_userdata, .{
                    .net_write = netWriteWindows(o.socket_handle, o.header, o.data, o.splat, o.control) catch |err| switch (err) {
                        error.Canceled => |e| return e,
                        else => |e| e,
                    },
                });
            },
        }
        index = submission.node.next;
    }
    b.submitted = .{ .head = .none, .tail = .none };
}

/// Since Windows only supports writing one contiguous buffer, returns the
/// first one, while also limiting it to a length representable by 32-bit
/// unsigned integer.
pub fn windowsWriteBuffer(header: []const u8, data: []const []const u8, splat: usize) []const u8 {
    const buffer = b: {
        if (header.len != 0) break :b header;
        for (data[0 .. data.len - 1]) |buffer| {
            if (buffer.len != 0) break :b buffer;
        }
        if (splat == 0) return &.{};
        break :b data[data.len - 1];
    };
    return buffer[0..std.math.lossyCast(u32, buffer.len)];
}

pub fn dirCreateDirWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = permissions; // TODO use this value

    const sub_path_w = try sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const attr: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w.span())) null else dir.handle,
        .Attributes = .{ .INHERIT = false },
        .ObjectName = @constCast(&windows.UNICODE_STRING.init(sub_path_w.span())),
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var sub_dir_handle: windows.HANDLE = undefined;
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var attempt: u5 = 0;
    var syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtCreateFile(
        &sub_dir_handle,
        .{
            .GENERIC = .{ .READ = true },
            .STANDARD = .{ .SYNCHRONIZE = true },
        },
        &attr,
        &io_status_block,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS,
        .CREATE,
        .{
            .DIRECTORY_FILE = true,
            .NON_DIRECTORY_FILE = false,
            .IO = .SYNCHRONOUS_NONALERT,
            .OPEN_REPARSE_POINT = false,
        },
        null,
        0,
    )) {
        .SUCCESS => {
            syscall.finish();
            windows.CloseHandle(sub_dir_handle);
            return;
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
            if (max_windows_kernel_bug_retries - attempt == 0) return error.Unexpected;
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
            if (max_windows_kernel_bug_retries - attempt == 0) return error.Unexpected;
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
        .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
        .OBJECT_NAME_COLLISION => return syscall.fail(error.PathAlreadyExists),
        .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
        .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
        .INVALID_PARAMETER => |status| return syscall.ntstatusBug(status),
        .OBJECT_PATH_SYNTAX_BAD => |status| return syscall.ntstatusBug(status),
        .INVALID_HANDLE => |status| return syscall.ntstatusBug(status),
        else => |status| return syscall.unexpectedNtstatus(status),
    };
}

pub fn dirCreateDirPathOpenWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.OpenOptions,
) Dir.CreateDirPathOpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const w = windows;

    _ = permissions; // TODO apply these permissions

    var it = Dir.path.componentIterator(sub_path);
    // If there are no components in the path, then create a dummy component with the full path.
    var component: Dir.path.NativeComponentIterator.Component = it.last() orelse .{
        .name = "",
        .path = sub_path,
    };

    components: while (true) {
        const sub_path_w = try sliceToPrefixedFileW(dir.handle, component.path, .{});
        const attr: windows.OBJECT.ATTRIBUTES = .{
            .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w.span())) null else dir.handle,
            .ObjectName = @constCast(&sub_path_w.string()),
        };
        const is_last = it.peekNext() == null;
        var result: Dir = .{ .handle = undefined };
        var iosb: w.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (w.ntdll.NtCreateFile(
            &result.handle,
            .{
                .SPECIFIC = .{ .FILE_DIRECTORY = .{
                    .LIST = options.iterate,
                    .READ_EA = true,
                    .READ_ATTRIBUTES = true,
                    .TRAVERSE = true,
                } },
                .STANDARD = .{
                    .RIGHTS = .READ,
                    .SYNCHRONIZE = true,
                },
            },
            &attr,
            &iosb,
            null,
            .{ .NORMAL = true },
            .VALID_FLAGS,
            if (is_last) .OPEN_IF else .CREATE,
            .{
                .DIRECTORY_FILE = true,
                .IO = .SYNCHRONOUS_NONALERT,
                .OPEN_FOR_BACKUP_INTENT = true,
                .OPEN_REPARSE_POINT = !options.follow_symlinks,
            },
            null,
            0,
        )) {
            .SUCCESS => {
                syscall.finish();
                component = it.next() orelse return result;
                w.CloseHandle(result.handle);
                continue :components;
            },
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_COLLISION => {
                syscall.finish();
                assert(!is_last);
                // stat the file and return an error if it's not a directory
                // this is important because otherwise a dangling symlink
                // could cause an infinite loop
                const fstat = try dirStatFileWindows(t, dir, component.path, .{
                    .follow_symlinks = options.follow_symlinks,
                });
                if (fstat.kind != .directory) return error.NotDir;

                component = it.next().?;
                continue :components;
            },

            .OBJECT_NAME_NOT_FOUND,
            .OBJECT_PATH_NOT_FOUND,
            => {
                syscall.finish();
                component = it.previous() orelse return error.FileNotFound;
                continue :components;
            },

            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            // This can happen if the directory has 'List folder contents' permission set to 'Deny'
            // and the directory is trying to be opened for iteration.
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .DISK_FULL => return syscall.fail(error.NoSpaceLeft),
            .INVALID_PARAMETER => |s| return syscall.ntstatusBug(s),
            else => |s| return syscall.unexpectedNtstatus(s),
        };
    }
}

pub fn dirStatFileWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const file = try dirOpenFileWindows(t, dir, sub_path, .{
        .follow_symlinks = options.follow_symlinks,
    });
    defer windows.CloseHandle(file.handle);
    return fileStatWindows(t, file);
}

pub fn windowsGetFileDevice(file: File) error{ Canceled, AccessDenied, Unexpected }!windows.CTL_CODE.FILE_DEVICE {
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var device_info: windows.FILE.FS_DEVICE_INFORMATION = undefined;
    {
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtQueryVolumeInformationFile(
            file.handle,
            &io_status_block,
            &device_info,
            @sizeOf(windows.FILE.FS_DEVICE_INFORMATION),
            .Device,
        )) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            else => |s| return syscall.unexpectedNtstatus(s),
        };
    }
    return device_info.DeviceType.FileDevice;
}

pub fn fileStatWindows(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const block_size: u32 = if (t.systemBasicInformation()) |sbi|
        @intCast(@max(sbi.PageSize, sbi.AllocationGranularity))
    else
        std.heap.page_size_max;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var info: windows.FILE.ALL_INFORMATION = undefined;
    {
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtQueryInformationFile(
            file.handle,
            &io_status_block,
            &info,
            @sizeOf(windows.FILE.ALL_INFORMATION),
            .All,
        )) {
            .SUCCESS => break syscall.finish(),
            // Buffer overflow here indicates that there is more information available than was able to be stored in the buffer
            // size provided. This is treated as success because the type of variable-length information that this would be relevant for
            // (name, volume name, etc) we don't care about.
            .BUFFER_OVERFLOW => break syscall.finish(),
            .INVALID_PARAMETER, // SERIAL_PORT devices like AUX, COM1, etc
            .INVALID_DEVICE_REQUEST, // CONSOLE, etc devices
            .INVALID_INFO_CLASS, // NULL, etc devices
            => {
                syscall.finish();
                const device = try windowsGetFileDevice(file);
                return .{
                    .inode = @intCast(@intFromPtr(file.handle)),
                    .size = 0,
                    .permissions = .default_file,
                    .kind = switch (device) {
                        // These are classified as FILE_TYPE_CHAR by GetFileType
                        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype
                        // (GetFileType calls NtQueryVolumeInformationFile with FS_DEVICE_INFORMATION)
                        .CONSOLE, .NULL, .SERIAL_PORT => .character_device,
                        else => .unknown,
                    },
                    // Match the times that NtQueryInformationFile returns for named pipes.
                    .atime = windows.fromSysTime(0),
                    .mtime = windows.fromSysTime(0),
                    .ctime = windows.fromSysTime(0),
                    .nlink = 1,
                    .block_size = block_size,
                };
            },
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |s| return syscall.unexpectedNtstatus(s),
        };
    }
    return .{
        .inode = info.InternalInformation.IndexNumber,
        .size = @as(u64, @bitCast(info.StandardInformation.EndOfFile)),
        .permissions = .default_file,
        .kind = if (info.BasicInformation.FileAttributes.REPARSE_POINT) reparse_point: {
            var tag_info: windows.FILE.ATTRIBUTE_TAG_INFO = undefined;
            const syscall: Syscall = try .start();
            while (true) switch (windows.ntdll.NtQueryInformationFile(
                file.handle,
                &io_status_block,
                &tag_info,
                @sizeOf(windows.FILE.ATTRIBUTE_TAG_INFO),
                .AttributeTag,
            )) {
                .SUCCESS => break syscall.finish(),
                // INFO_LENGTH_MISMATCH and ACCESS_DENIED are the only documented possible errors
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d295752f-ce89-4b98-8553-266d37c84f0e
                .INFO_LENGTH_MISMATCH => |err| return syscall.ntstatusBug(err),
                .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |s| return syscall.unexpectedNtstatus(s),
            };
            if (tag_info.ReparseTag.IsSurrogate) break :reparse_point .sym_link;
            // Unknown reparse point
            break :reparse_point .unknown;
        } else if (info.BasicInformation.FileAttributes.DIRECTORY)
            .directory
        else switch (try windowsGetFileDevice(file)) {
            .NAMED_PIPE => .named_pipe,
            else => .file,
        },
        .atime = windows.fromSysTime(info.BasicInformation.LastAccessTime),
        .mtime = windows.fromSysTime(info.BasicInformation.LastWriteTime),
        .ctime = windows.fromSysTime(info.BasicInformation.ChangeTime),
        .nlink = info.StandardInformation.NumberOfLinks,
        .block_size = block_size,
    };
}

pub fn dirAccessWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.AccessOptions,
) Dir.AccessError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    _ = options; // TODO

    if (std.mem.eql(u8, sub_path, ".") or std.mem.eql(u8, sub_path, "..")) return;
    const sub_path_w = try sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const attr: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w.span())) null else dir.handle,
        .ObjectName = @constCast(&sub_path_w.string()),
    };
    var basic_info: windows.FILE.BASIC_INFORMATION = undefined;
    const syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtQueryAttributesFile(&attr, &basic_info)) {
        .SUCCESS => return syscall.finish(),
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .OBJECT_NAME_INVALID => |err| return syscall.ntstatusBug(err),
        .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
        .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
        .OBJECT_PATH_SYNTAX_BAD => |err| return syscall.ntstatusBug(err),
        else => |rc| return syscall.unexpectedNtstatus(rc),
    };
}

pub fn dirCreateFileWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: Dir.CreateFileOptions,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (std.mem.eql(u8, sub_path, ".")) return error.IsDir;
    if (std.mem.eql(u8, sub_path, "..")) return error.IsDir;

    const sub_path_w = try sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const attr: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w.span())) null else dir.handle,
        .ObjectName = @constCast(&sub_path_w.string()),
    };
    const create_disposition: windows.FILE.CREATE_DISPOSITION = if (flags.exclusive)
        .CREATE
    else if (flags.truncate)
        .OVERWRITE_IF
    else
        .OPEN_IF;

    const access_mask: windows.ACCESS_MASK = .{
        .STANDARD = .{ .SYNCHRONIZE = true },
        .GENERIC = .{
            .WRITE = true,
            .READ = flags.read,
        },
    };

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var attempt: u5 = 0;
    var handle: windows.HANDLE = undefined;
    var syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtCreateFile(
        &handle,
        access_mask,
        &attr,
        &io_status_block,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS, // share access
        create_disposition,
        .{
            .NON_DIRECTORY_FILE = true,
            .IO = .SYNCHRONOUS_NONALERT,
        },
        null,
        0,
    )) {
        .SUCCESS => {
            syscall.finish();
            break;
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
            if (max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
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
            // call has failed. Here, we simulate the kernel bug being
            // fixed by sleeping and retrying until the error goes away.
            syscall.finish();
            if (max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
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
        .DISK_FULL => return syscall.fail(error.NoSpaceLeft),
        .INVALID_PARAMETER => |status| return syscall.ntstatusBug(status),
        .OBJECT_PATH_SYNTAX_BAD => |status| return syscall.ntstatusBug(status),
        .INVALID_HANDLE => |status| return syscall.ntstatusBug(status),
        else => |status| return syscall.unexpectedNtstatus(status),
    };
    errdefer windows.CloseHandle(handle);

    const exclusive = switch (flags.lock) {
        .none => return .{
            .handle = handle,
            .flags = .{ .nonblocking = false },
        },
        .shared => false,
        .exclusive => true,
    };

    syscall = try .start();
    while (true) switch (windows.ntdll.NtLockFile(
        handle,
        null,
        null,
        null,
        &io_status_block,
        &windows_lock_range_off,
        &windows_lock_range_len,
        null,
        .fromBool(flags.lock_nonblocking),
        .fromBool(exclusive),
    )) {
        .SUCCESS => {
            syscall.finish();
            return .{
                .handle = handle,
                .flags = .{ .nonblocking = false },
            };
        },
        .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
        .LOCK_NOT_GRANTED => return syscall.fail(error.WouldBlock),
        .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
        else => |status| return syscall.unexpectedNtstatus(status),
    };
}

pub fn dirOpenFileWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: Dir.OpenFileOptions,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const sub_path_w_array = try sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const sub_path_w = sub_path_w_array.span();
    const dir_handle = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w)) null else dir.handle;
    return dirOpenFileWtf16(dir_handle, sub_path_w, flags);
}

pub fn dirOpenFileWtf16(
    dir_handle: ?windows.HANDLE,
    sub_path_w: []const u16,
    flags: Dir.OpenFileOptions,
) File.OpenError!File {
    const allow_directory = flags.allow_directory and !flags.isWrite();
    if (!allow_directory and std.mem.eql(u16, sub_path_w, &.{'.'})) return error.IsDir;
    if (!allow_directory and std.mem.eql(u16, sub_path_w, &.{ '.', '.' })) return error.IsDir;
    const w = windows;

    var io_status_block: w.IO_STATUS_BLOCK = undefined;
    var attempt: u5 = 0;
    var syscall: Syscall = try .start();
    const handle = while (true) {
        var result: w.HANDLE = undefined;
        switch (w.ntdll.NtCreateFile(
            &result,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{
                    .READ = flags.isRead(),
                    .WRITE = flags.isWrite(),
                },
            },
            &.{
                .RootDirectory = dir_handle,
                .ObjectName = @constCast(&w.UNICODE_STRING.init(sub_path_w)),
            },
            &io_status_block,
            null,
            .{ .NORMAL = true },
            .VALID_FLAGS,
            .OPEN,
            .{
                .IO = .SYNCHRONOUS_NONALERT,
                .NON_DIRECTORY_FILE = !allow_directory,
                .OPEN_REPARSE_POINT = !flags.follow_symlinks,
            },
            null,
            0,
        )) {
            .SUCCESS => {
                syscall.finish();
                break result;
            },
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .BAD_NETWORK_PATH => return syscall.fail(error.NetworkNotFound), // \\server was not found
            .BAD_NETWORK_NAME => return syscall.fail(error.NetworkNotFound), // \\server was found but \\server\share wasn't
            .NO_MEDIA_IN_DEVICE => return syscall.fail(error.NoDevice),
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
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
                if (max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
                try parking_sleep.sleep(.{ .duration = .{
                    .raw = .fromMilliseconds((@as(u32, 1) << attempt) >> 1),
                    .clock = .awake,
                } });
                attempt += 1;
                syscall = try .start();
                continue;
            },
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .PIPE_BUSY => return syscall.fail(error.PipeBusy),
            .PIPE_NOT_AVAILABLE => return syscall.fail(error.NoDevice),
            .OBJECT_PATH_SYNTAX_BAD => |err| return syscall.ntstatusBug(err),
            .OBJECT_NAME_COLLISION => return syscall.fail(error.PathAlreadyExists),
            .FILE_IS_A_DIRECTORY => return syscall.fail(error.IsDir),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
            .INVALID_HANDLE => |err| return syscall.ntstatusBug(err),
            .DELETE_PENDING => {
                // This error means that there *was* a file in this location on
                // the file system, but it was deleted. However, the OS is not
                // finished with the deletion operation, and so this CreateFile
                // call has failed. Here, we simulate the kernel bug being
                // fixed by sleeping and retrying until the error goes away.
                syscall.finish();
                if (max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
                try parking_sleep.sleep(.{ .duration = .{
                    .raw = .fromMilliseconds((@as(u32, 1) << attempt) >> 1),
                    .clock = .awake,
                } });
                attempt += 1;
                syscall = try .start();
                continue;
            },
            .VIRUS_INFECTED, .VIRUS_DELETED => return syscall.fail(error.AntivirusInterference),
            else => |rc| return syscall.unexpectedNtstatus(rc),
        }
    };
    errdefer w.CloseHandle(handle);

    const exclusive = switch (flags.lock) {
        .none => return .{
            .handle = handle,
            .flags = .{ .nonblocking = false },
        },
        .shared => false,
        .exclusive => true,
    };
    syscall = try .start();
    while (true) switch (w.ntdll.NtLockFile(
        handle,
        null,
        null,
        null,
        &io_status_block,
        &windows_lock_range_off,
        &windows_lock_range_len,
        null,
        .fromBool(flags.lock_nonblocking),
        .fromBool(exclusive),
    )) {
        .SUCCESS => break syscall.finish(),
        .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
        .LOCK_NOT_GRANTED => return syscall.fail(error.WouldBlock),
        .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
        else => |status| return syscall.unexpectedNtstatus(status),
    };
    return .{
        .handle = handle,
        .flags = .{ .nonblocking = false },
    };
}

pub fn dirOpenDirWindows(
    dir: Dir,
    sub_path_w: []const u16,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    const w = windows;

    var io_status_block: w.IO_STATUS_BLOCK = undefined;
    var result: Dir = .{ .handle = undefined };

    const attr: w.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w)) null else dir.handle,
        .ObjectName = @constCast(&w.UNICODE_STRING.init(sub_path_w)),
    };

    const syscall: Syscall = try .start();
    while (true) switch (w.ntdll.NtCreateFile(
        &result.handle,
        // TODO remove some of these flags if options.access_sub_paths is false
        .{
            .SPECIFIC = .{ .FILE_DIRECTORY = .{
                .LIST = options.iterate,
                .READ_EA = true,
                .TRAVERSE = true,
                .READ_ATTRIBUTES = true,
            } },
            .STANDARD = .{
                .RIGHTS = .READ,
                .SYNCHRONIZE = true,
            },
        },
        &attr,
        &io_status_block,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS,
        .OPEN,
        .{
            .DIRECTORY_FILE = true,
            .IO = .SYNCHRONOUS_NONALERT,
            .OPEN_FOR_BACKUP_INTENT = true,
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
        .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
        .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .OBJECT_NAME_COLLISION => |err| return w.statusBug(err),
        .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
        // This can happen if the directory has 'List folder contents' permission set to 'Deny'
        // and the directory is trying to be opened for iteration.
        .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
        .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
        else => |rc| return syscall.unexpectedNtstatus(rc),
    };
}

pub fn dirReadWindows(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const w = windows;

    // We want to be able to use the `dr.buffer` for both the NtQueryDirectoryFile call (which
    // returns WTF-16 names) *and* as a buffer for storing those WTF-16 names as WTF-8 to be able
    // to return them in `Dir.Entry.name`. However, the problem that needs to be overcome in order to do
    // that is that each WTF-16 code unit can be encoded as a maximum of 3 WTF-8 bytes, which means
    // that it's not guaranteed that the memory used for the WTF-16 name will be sufficient
    // for the WTF-8 encoding of the same name (for example, € is encoded as one WTF-16 code unit,
    // [2 bytes] but encoded in WTF-8 as 3 bytes).
    //
    // The approach taken here is to "reserve" enough space in the `dr.buffer` to ensure that
    // at least one entry with the maximum possible WTF-8 name length can be stored without clobbering
    // any entries that follow it. That is, we determine how much space is needed to allow that,
    // and then only provide the remaining portion of `dr.buffer` to the NtQueryDirectoryFile
    // call. The WTF-16 names can then be safely converted using the full `dr.buffer` slice, making
    // sure that each name can only potentially overwrite the data of its own entry.
    //
    // The worst case, where an entry's name is both the maximum length of a component and
    // made up entirely of code points that are encoded as one WTF-16 code unit/three WTF-8 bytes,
    // would therefore look like the diagram below, and only one entry would be able to be returned:
    //
    //     |   reserved  | remaining unreserved buffer |
    //                   | entry 1 | entry 2 |   ...   |
    //     | wtf-8 name of entry 1 |
    //
    // However, in the average case we will be able to store more than one WTF-8 name at a time in the
    // available buffer and therefore we will be able to populate more than one `Dir.Entry` at a time.
    // That might look something like this (where name 1, name 2, etc are the converted WTF-8 names):
    //
    //     |   reserved  | remaining unreserved buffer |
    //                   | entry 1 | entry 2 |   ...   |
    //     | name 1 | name 2 | name 3 | name 4 |  ...  |
    //
    // Note: More than the minimum amount of space could be reserved to make the "worst case"
    // less likely, but since the worst-case also requires a maximum length component to matter,
    // it's unlikely for it to become a problem in normal scenarios even if all names on the filesystem
    // are made up of non-ASCII characters that have the "one WTF-16 code unit <-> three WTF-8 bytes"
    // property (e.g. code points >= U+0800 and <= U+FFFF), as it's unlikely for a significant
    // number of components to be maximum length.

    // We need `3 * NAME_MAX` bytes to store a max-length component as WTF-8 safely.
    // Because needing to store a max-length component depends on a `FileName` *with* the maximum
    // component length, we know that the corresponding populated `FILE_BOTH_DIR_INFORMATION` will
    // be of size `@sizeOf(w.FILE_BOTH_DIR_INFORMATION) + 2 * NAME_MAX` bytes, so we only need to
    // reserve enough to get us to up to having `3 * NAME_MAX` bytes available when taking into account
    // that we have the ability to write over top of the reserved memory + the full footprint of that
    // particular `FILE_BOTH_DIR_INFORMATION`.
    const max_info_len = @sizeOf(w.FILE_BOTH_DIR_INFORMATION) + w.NAME_MAX * 2;
    const info_align = @alignOf(w.FILE_BOTH_DIR_INFORMATION);
    const reserve_needed = std.mem.alignForward(usize, Dir.max_name_bytes, info_align) - max_info_len;
    const unreserved_start = std.mem.alignForward(usize, reserve_needed, info_align);
    const unreserved_buffer = dr.buffer[unreserved_start..];
    // This is enforced by `Dir.Reader`
    assert(unreserved_buffer.len >= max_info_len);

    var name_index: usize = 0;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;

            var io_status_block: w.IO_STATUS_BLOCK = undefined;
            const syscall: Syscall = try .start();
            const rc = while (true) switch (w.ntdll.NtQueryDirectoryFile(
                dr.dir.handle,
                null,
                null,
                null,
                &io_status_block,
                unreserved_buffer.ptr,
                std.math.lossyCast(w.ULONG, unreserved_buffer.len),
                .BothDirectory,
                .FALSE,
                null,
                .fromBool(dr.state == .reset),
            )) {
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |rc| {
                    syscall.finish();
                    break rc;
                },
            };
            dr.state = .reading;
            if (io_status_block.Information == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = io_status_block.Information;
            switch (rc) {
                .SUCCESS => {},
                .ACCESS_DENIED => return error.AccessDenied, // Double-check that the Dir was opened with iteration ability
                else => return w.unexpectedStatus(rc),
            }
        }

        // While the official API docs guarantee FILE_BOTH_DIR_INFORMATION to be aligned properly
        // this may not always be the case (e.g. due to faulty VM/sandboxing tools)
        const dir_info: *align(2) w.FILE_BOTH_DIR_INFORMATION = @ptrCast(@alignCast(&unreserved_buffer[dr.index]));
        const backtrack_index = dr.index;
        if (dir_info.NextEntryOffset != 0) {
            dr.index += dir_info.NextEntryOffset;
        } else {
            dr.index = dr.end;
        }

        const name_wtf16le = @as([*]u16, @ptrCast(&dir_info.FileName))[0 .. dir_info.FileNameLength / 2];

        if (std.mem.eql(u16, name_wtf16le, &[_]u16{'.'}) or std.mem.eql(u16, name_wtf16le, &[_]u16{ '.', '.' })) {
            continue;
        }

        // Read any relevant information from the `dir_info` now since it's possible the WTF-8
        // name will overwrite it.
        const kind: File.Kind = blk: {
            const attrs = dir_info.FileAttributes;
            if (attrs.REPARSE_POINT) break :blk .sym_link;
            if (attrs.DIRECTORY) break :blk .directory;
            break :blk .file;
        };
        const inode: File.INode = dir_info.FileIndex;

        // If there's no more space for WTF-8 names without bleeding over into
        // the remaining unprocessed entries, then backtrack and return what we have so far.
        if (name_index + std.unicode.calcWtf8Len(name_wtf16le) > unreserved_start + dr.index) {
            // We should always be able to fit at least one entry into the buffer no matter what
            assert(buffer_index != 0);
            dr.index = backtrack_index;
            break;
        }

        const name_buf = dr.buffer[name_index..];
        const name_wtf8_len = std.unicode.wtf16LeToWtf8(name_buf, name_wtf16le);
        const name_wtf8 = name_buf[0..name_wtf8_len];
        name_index += name_wtf8_len;

        buffer[buffer_index] = .{
            .name = name_wtf8,
            .kind = kind,
            .inode = inode,
        };
        buffer_index += 1;
    }

    return buffer_index;
}

pub fn dirRealPathFileWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, out_buffer: []u8) Dir.RealPathFileError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_name_w = try sliceToPrefixedFileW(dir.handle, sub_path, .{});

    const h_file = handle: {
        if (OpenFile(path_name_w.span(), .{
            .dir = dir.handle,
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
            else => |e| return e,
        }
    };
    defer windows.CloseHandle(h_file);

    // We can re-use the path buffer for the WTF-16 representation since
    // we don't need the prefixed path anymore
    return realPathWindowsBuf(h_file, out_buffer, &path_name_w.data);
}

pub fn realPathWindows(h_file: windows.HANDLE, out_buffer: []u8) File.RealPathError!usize {
    var wide_buf: [windows.PATH_MAX_WIDE]u16 = undefined;
    return realPathWindowsBuf(h_file, out_buffer, &wide_buf);
}

pub fn realPathWindowsBuf(h_file: windows.HANDLE, out_buffer: []u8, wtf16_buffer: []u16) File.RealPathError!usize {
    const wide_slice = try GetFinalPathNameByHandle(h_file, .{}, wtf16_buffer);

    const len = std.unicode.calcWtf8Len(wide_slice);
    if (len > out_buffer.len)
        return error.NameTooLong;

    return std.unicode.wtf16LeToWtf8(out_buffer, wide_slice);
}

/// Specifies how to format volume path in the result of `GetFinalPathNameByHandle`.
/// Defaults to DOS volume names.
pub const GetFinalPathNameByHandleFormat = struct {
    volume_name: enum {
        /// Format as DOS volume name
        Dos,
        /// Format as NT volume name
        Nt,
    } = .Dos,
};

pub const GetFinalPathNameByHandleError = error{
    AccessDenied,
    FileNotFound,
    NameTooLong,
    /// The volume does not contain a recognized file system. File system
    /// drivers might not be loaded, or the volume may be corrupt.
    UnrecognizedVolume,
} || Io.Cancelable || Io.UnexpectedError;

/// Returns canonical (normalized) path of handle.
/// Use `GetFinalPathNameByHandleFormat` to specify whether the path is meant to include
/// NT or DOS volume name (e.g., `\Device\HarddiskVolume0\foo.txt` versus `C:\foo.txt`).
/// If DOS volume name format is selected, note that this function does *not* prepend
/// `\\?\` prefix to the resultant path.
pub fn GetFinalPathNameByHandle(
    hFile: windows.HANDLE,
    fmt: GetFinalPathNameByHandleFormat,
    out_buffer: []u16,
) GetFinalPathNameByHandleError![]u16 {
    const final_path = QueryObjectName(hFile, out_buffer) catch |err| switch (err) {
        // we assume InvalidHandle is close enough to FileNotFound in semantics
        // to not further complicate the error set
        error.InvalidHandle => return error.FileNotFound,
        else => |e| return e,
    };

    switch (fmt.volume_name) {
        .Nt => {
            // the returned path is already in .Nt format
            return final_path;
        },
        .Dos => {
            // parse the string to separate volume path from file path
            const device_prefix = std.unicode.utf8ToUtf16LeStringLiteral("\\Device\\");

            // We aren't entirely sure of the structure of the path returned by
            // QueryObjectName in all contexts/environments.
            // This code is written to cover the various cases that have
            // been encountered and solved appropriately. But note that there's
            // no easy way to verify that they have all been tackled!
            // (Unless you, the reader knows of one then please do action that!)
            if (!std.mem.startsWith(u16, final_path, device_prefix)) {
                // Wine seems to return NT namespaced paths starting with \??\ from QueryObjectName
                // (e.g. `\??\Z:\some\path\to\a\file.txt`), in which case we can just strip the
                // prefix to turn it into an absolute path.
                // https://github.com/ziglang/zig/issues/26029
                // https://bugs.winehq.org/show_bug.cgi?id=39569
                return windows.ntToWin32Namespace(final_path, out_buffer) catch |err| switch (err) {
                    error.NotNtPath => return error.Unexpected,
                    error.NameTooLong => |e| return e,
                };
            }

            const file_path_begin_index = std.mem.findPos(u16, final_path, device_prefix.len, &[_]u16{'\\'}) orelse unreachable;
            const volume_name_u16 = final_path[0..file_path_begin_index];
            const device_name_u16 = volume_name_u16[device_prefix.len..];
            const file_name_u16 = final_path[file_path_begin_index..];

            // MUP is Multiple UNC Provider, and indicates that the path is a UNC
            // path. In this case, the canonical UNC path can be gotten by just
            // dropping the \Device\Mup\ and making sure the path begins with \\
            if (std.mem.eql(u16, device_name_u16, std.unicode.utf8ToUtf16LeStringLiteral("Mup"))) {
                out_buffer[0] = '\\';
                @memmove(out_buffer[1..][0..file_name_u16.len], file_name_u16);
                return out_buffer[0 .. 1 + file_name_u16.len];
            }

            // Get DOS volume name. DOS volume names are actually symbolic link objects to the
            // actual NT volume. For example:
            // (NT) \Device\HarddiskVolume4 => (DOS) \DosDevices\C: == (DOS) C:
            const MIN_SIZE = @sizeOf(windows.MOUNTMGR_MOUNT_POINT) + windows.MAX_PATH;
            // We initialize the input buffer to all zeros for convenience since
            // `DeviceIoControl` with `IOCTL_MOUNTMGR_QUERY_POINTS` expects this.
            var input_buf: [MIN_SIZE]u8 align(@alignOf(windows.MOUNTMGR_MOUNT_POINT)) = @splat(0);
            var output_buf: [MIN_SIZE * 4]u8 align(@alignOf(windows.MOUNTMGR_MOUNT_POINTS)) = undefined;

            // This surprising path is a filesystem path to the mount manager on Windows.
            // Source: https://stackoverflow.com/questions/3012828/using-ioctl-mountmgr-query-points
            // This is the NT namespaced version of \\.\MountPointManager
            const mgmt_path_u16 = std.unicode.utf8ToUtf16LeStringLiteral("\\??\\MountPointManager");
            const mgmt_handle = OpenFile(mgmt_path_u16, .{
                .access_mask = .{ .STANDARD = .{ .SYNCHRONIZE = true } },
                .creation = .OPEN,
            }) catch |err| switch (err) {
                error.IsDir => return error.Unexpected,
                error.NotDir => return error.Unexpected,
                error.NoDevice => return error.Unexpected,
                error.AccessDenied => return error.Unexpected,
                error.PipeBusy => return error.Unexpected,
                error.FileBusy => return error.Unexpected,
                error.PathAlreadyExists => return error.Unexpected,
                error.WouldBlock => return error.Unexpected,
                error.NetworkNotFound => return error.Unexpected,
                error.AntivirusInterference => return error.Unexpected,
                error.BadPathName => return error.Unexpected,
                else => |e| return e,
            };
            defer windows.CloseHandle(mgmt_handle);

            var input_struct: *windows.MOUNTMGR_MOUNT_POINT = @ptrCast(&input_buf[0]);
            input_struct.DeviceNameOffset = @sizeOf(windows.MOUNTMGR_MOUNT_POINT);
            input_struct.DeviceNameLength = @intCast(volume_name_u16.len * 2);
            @memcpy(input_buf[@sizeOf(windows.MOUNTMGR_MOUNT_POINT)..][0 .. volume_name_u16.len * 2], @as([*]const u8, @ptrCast(volume_name_u16.ptr)));

            switch ((try deviceIoControl(&.{
                .file = .{ .handle = mgmt_handle, .flags = .{ .nonblocking = false } },
                .code = windows.IOCTL.MOUNTMGR.QUERY_POINTS,
                .in = &input_buf,
                .out = &output_buf,
            })).u.Status) {
                .SUCCESS => {},
                .CANCELLED => unreachable,
                .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
                else => |status| return windows.unexpectedStatus(status),
            }
            const mount_points_struct: *const windows.MOUNTMGR_MOUNT_POINTS = @ptrCast(&output_buf[0]);

            const mount_points = @as(
                [*]const windows.MOUNTMGR_MOUNT_POINT,
                @ptrCast(&mount_points_struct.MountPoints[0]),
            )[0..mount_points_struct.NumberOfMountPoints];

            for (mount_points) |mount_point| {
                const symlink = @as(
                    [*]const u16,
                    @ptrCast(@alignCast(&output_buf[mount_point.SymbolicLinkNameOffset])),
                )[0 .. mount_point.SymbolicLinkNameLength / 2];

                // Look for `\DosDevices\` prefix. We don't really care if there are more than one symlinks
                // with traditional DOS drive letters, so pick the first one available.
                var prefix_buf = std.unicode.utf8ToUtf16LeStringLiteral("\\DosDevices\\");
                const prefix = prefix_buf[0..prefix_buf.len];

                if (std.mem.startsWith(u16, symlink, prefix)) {
                    const drive_letter = symlink[prefix.len..];

                    if (out_buffer.len < drive_letter.len + file_name_u16.len) return error.NameTooLong;

                    @memcpy(out_buffer[0..drive_letter.len], drive_letter);
                    @memmove(out_buffer[drive_letter.len..][0..file_name_u16.len], file_name_u16);
                    const total_len = drive_letter.len + file_name_u16.len;

                    // Validate that DOS does not contain any spurious nul bytes.
                    assert(std.mem.findScalar(u16, out_buffer[0..total_len], 0) == null);

                    return out_buffer[0..total_len];
                } else if (mountmgrIsVolumeName(symlink)) {
                    // If the symlink is a volume GUID like \??\Volume{383da0b0-717f-41b6-8c36-00500992b58d},
                    // then it is a volume mounted as a path rather than a drive letter. We need to
                    // query the mount manager again to get the DOS path for the volume.

                    // 49 is the maximum length accepted by mountmgrIsVolumeName
                    const vol_input_size = @sizeOf(windows.MOUNTMGR_TARGET_NAME) + (49 * 2);
                    var vol_input_buf: [vol_input_size]u8 align(@alignOf(windows.MOUNTMGR_TARGET_NAME)) = @splat(0);
                    // Note: If the path exceeds MAX_PATH, the Disk Management GUI doesn't accept the full path,
                    // and instead if must be specified using a shortened form (e.g. C:\FOO~1\BAR~1\<...>).
                    // However, just to be sure we can handle any path length, we use PATH_MAX_WIDE here.
                    const min_output_size = @sizeOf(windows.MOUNTMGR_VOLUME_PATHS) + (windows.PATH_MAX_WIDE * 2);
                    var vol_output_buf: [min_output_size]u8 align(@alignOf(windows.MOUNTMGR_VOLUME_PATHS)) = undefined;

                    var vol_input_struct: *windows.MOUNTMGR_TARGET_NAME = @ptrCast(&vol_input_buf[0]);
                    vol_input_struct.DeviceNameLength = @intCast(symlink.len * 2);
                    @memcpy(@as([*]windows.WCHAR, &vol_input_struct.DeviceName)[0..symlink.len], symlink);

                    switch ((try deviceIoControl(&.{
                        .file = .{ .handle = mgmt_handle, .flags = .{ .nonblocking = true } },
                        .code = windows.IOCTL.MOUNTMGR.QUERY_DOS_VOLUME_PATH,
                        .in = &vol_input_buf,
                        .out = &vol_output_buf,
                    })).u.Status) {
                        .SUCCESS => {},
                        .CANCELLED => unreachable,
                        .UNRECOGNIZED_VOLUME => return error.UnrecognizedVolume,
                        else => |status| return windows.unexpectedStatus(status),
                    }
                    const volume_paths_struct: *const windows.MOUNTMGR_VOLUME_PATHS = @ptrCast(&vol_output_buf[0]);
                    const volume_path = std.mem.sliceTo(@as(
                        [*]const u16,
                        &volume_paths_struct.MultiSz,
                    )[0 .. volume_paths_struct.MultiSzLength / 2], 0);

                    if (out_buffer.len < volume_path.len + file_name_u16.len) return error.NameTooLong;

                    // `out_buffer` currently contains the memory of `file_name_u16`, so it can overlap with where
                    // we want to place the filename before returning. Here are the possible overlapping cases:
                    //
                    // out_buffer:       [filename]
                    //       dest: [___(a)___] [___(b)___]
                    //
                    // In the case of (a), we need to copy forwards, and in the case of (b) we need
                    // to copy backwards. We also need to do this before copying the volume path because
                    // it could overwrite the file_name_u16 memory.
                    const file_name_dest = out_buffer[volume_path.len..][0..file_name_u16.len];
                    @memmove(file_name_dest, file_name_u16);
                    @memcpy(out_buffer[0..volume_path.len], volume_path);
                    const total_len = volume_path.len + file_name_u16.len;

                    // Validate that DOS does not contain any spurious nul bytes.
                    assert(std.mem.findScalar(u16, out_buffer[0..total_len], 0) == null);

                    return out_buffer[0..total_len];
                }
            }

            // If we've ended up here, then something went wrong/is corrupted in the OS,
            // so error out!
            return error.FileNotFound;
        },
    }
}

test GetFinalPathNameByHandle {
    if (builtin.os.tag != .windows)
        return;

    //any file will do
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const handle = tmp.dir.handle;
    var buffer: [windows.PATH_MAX_WIDE]u16 = undefined;

    //check with sufficient size
    const nt_path = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, &buffer);
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, &buffer);

    const required_len_in_u16 = nt_path.len + @divExact(@intFromPtr(nt_path.ptr) - @intFromPtr(&buffer), 2) + 1;
    //check with insufficient size
    try std.testing.expectError(error.NameTooLong, GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, buffer[0 .. required_len_in_u16 - 1]));
    try std.testing.expectError(error.NameTooLong, GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, buffer[0 .. required_len_in_u16 - 1]));

    //check with exactly-sufficient size
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Nt }, buffer[0..required_len_in_u16]);
    _ = try GetFinalPathNameByHandle(handle, .{ .volume_name = .Dos }, buffer[0..required_len_in_u16]);
}

/// Equivalent to the MOUNTMGR_IS_VOLUME_NAME macro in mountmgr.h
pub fn mountmgrIsVolumeName(name: []const u16) bool {
    return (name.len == 48 or (name.len == 49 and name[48] == std.mem.nativeToLittle(u16, '\\'))) and
        name[0] == std.mem.nativeToLittle(u16, '\\') and
        (name[1] == std.mem.nativeToLittle(u16, '?') or name[1] == std.mem.nativeToLittle(u16, '\\')) and
        name[2] == std.mem.nativeToLittle(u16, '?') and
        name[3] == std.mem.nativeToLittle(u16, '\\') and
        std.mem.startsWith(u16, name[4..], std.unicode.utf8ToUtf16LeStringLiteral("Volume{")) and
        name[19] == std.mem.nativeToLittle(u16, '-') and
        name[24] == std.mem.nativeToLittle(u16, '-') and
        name[29] == std.mem.nativeToLittle(u16, '-') and
        name[34] == std.mem.nativeToLittle(u16, '-') and
        name[47] == std.mem.nativeToLittle(u16, '}');
}

test mountmgrIsVolumeName {
    @setEvalBranchQuota(2000);
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    try std.testing.expect(mountmgrIsVolumeName(L("\\\\?\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}")));
    try std.testing.expect(mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}")));
    try std.testing.expect(mountmgrIsVolumeName(L("\\\\?\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}\\")));
    try std.testing.expect(mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}\\")));
    try std.testing.expect(!mountmgrIsVolumeName(L("\\\\.\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}")));
    try std.testing.expect(!mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}\\foo")));
    try std.testing.expect(!mountmgrIsVolumeName(L("\\??\\Volume{383da0b0-717f-41b6-8c36-00500992b58}")));
}

pub const QueryObjectNameError = error{
    AccessDenied,
    InvalidHandle,
    NameTooLong,
    Unexpected,
};

pub fn QueryObjectName(handle: windows.HANDLE, out_buffer: []u16) QueryObjectNameError![]u16 {
    const out_buffer_aligned = std.mem.alignInSlice(out_buffer, @alignOf(windows.OBJECT.NAME_INFORMATION)) orelse return error.NameTooLong;

    const info: *windows.OBJECT.NAME_INFORMATION = @ptrCast(out_buffer_aligned);
    // buffer size is specified in bytes
    const out_buffer_len = std.math.cast(windows.ULONG, out_buffer_aligned.len * 2) orelse std.math.maxInt(windows.ULONG);
    // last argument would return the length required for full_buffer, not exposed here
    return switch (windows.ntdll.NtQueryObject(handle, .Name, info, out_buffer_len, null)) {
        .SUCCESS => {
            // info.Name from ObQueryNameString is documented to be empty if the object
            // was "unnamed", not sure if this can happen for file handles
            return if (info.Name.isEmpty()) error.Unexpected else info.Name.slice();
        },
        .ACCESS_DENIED => error.AccessDenied,
        .INVALID_HANDLE => error.InvalidHandle,
        // triggered when the buffer is too small for the OBJECT_NAME_INFORMATION object (.INFO_LENGTH_MISMATCH),
        // or if the buffer is too small for the file path returned (.BUFFER_OVERFLOW, .BUFFER_TOO_SMALL)
        .INFO_LENGTH_MISMATCH, .BUFFER_OVERFLOW, .BUFFER_TOO_SMALL => error.NameTooLong,
        else => |e| windows.unexpectedStatus(e),
    };
}

test QueryObjectName {
    if (builtin.os.tag != .windows)
        return;

    //any file will do; canonicalization works on NTFS junctions and symlinks, hardlinks remain separate paths.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const handle = tmp.dir.handle;
    var out_buffer: [windows.PATH_MAX_WIDE]u16 = undefined;

    const result_path = try QueryObjectName(handle, &out_buffer);
    const required_len_in_u16 = result_path.len + @divExact(@intFromPtr(result_path.ptr) - @intFromPtr(&out_buffer), 2) + 1;
    //insufficient size
    try std.testing.expectError(error.NameTooLong, QueryObjectName(handle, out_buffer[0 .. required_len_in_u16 - 1]));
    //exactly-sufficient size
    _ = try QueryObjectName(handle, out_buffer[0..required_len_in_u16]);
}

pub const Wtf16ToPrefixedFileWError = error{
    AccessDenied,
    FileNotFound,
} || Dir.PathNameError || Io.Cancelable || Io.UnexpectedError;

pub const Wtf16ToPrefixedFileWOptions = struct {
    allow_relative: bool = true,
};

/// Converts the `path` to WTF16, null-terminated. If the path contains any
/// namespace prefix, or is anything but a relative path (rooted, drive relative,
/// etc) the result will have the NT-style prefix `\??\`.
///
/// Similar to RtlDosPathNameToNtPathName_U with a few differences:
/// - Does not allocate on the heap.
/// - Relative paths are kept as relative unless they contain too many ..
///   components, in which case they are resolved against the `dir` if it
///   is non-null, or the CWD if it is null.
/// - Special case device names like COM1, NUL, etc are not handled specially (TODO)
/// - . and space are not stripped from the end of relative paths (potential TODO)
pub fn wToPrefixedFileW(dir: ?windows.HANDLE, path: [:0]const u16, options: Wtf16ToPrefixedFileWOptions) Wtf16ToPrefixedFileWError!WindowsPathSpace {
    const nt_prefix = [_]u16{ '\\', '?', '?', '\\' };
    if (windows.hasCommonNtPrefix(u16, path)) {
        // TODO: Figure out a way to design an API that can avoid the copy for NT,
        //       since it is always returned fully unmodified.
        var path_space: WindowsPathSpace = undefined;
        path_space.data[0..nt_prefix.len].* = nt_prefix;
        const len_after_prefix = path.len - nt_prefix.len;
        @memcpy(path_space.data[nt_prefix.len..][0..len_after_prefix], path[nt_prefix.len..]);
        path_space.len = path.len;
        path_space.data[path_space.len] = 0;
        return path_space;
    } else {
        const path_type = Dir.path.getWin32PathType(u16, path);
        var path_space: WindowsPathSpace = undefined;
        if (path_type == .local_device) switch (getLocalDevicePathType(u16, path)) {
            .verbatim => {
                path_space.data[0..nt_prefix.len].* = nt_prefix;
                const len_after_prefix = path.len - nt_prefix.len;
                @memcpy(path_space.data[nt_prefix.len..][0..len_after_prefix], path[nt_prefix.len..]);
                path_space.len = path.len;
                path_space.data[path_space.len] = 0;
                return path_space;
            },
            .local_device, .fake_verbatim => {
                const path_byte_len = windows.ntdll.RtlGetFullPathName_U(
                    path.ptr,
                    path_space.data.len * 2,
                    &path_space.data,
                    null,
                );
                if (path_byte_len == 0) {
                    // TODO: This may not be the right error
                    return error.BadPathName;
                } else if (path_byte_len / 2 > path_space.data.len) {
                    return error.NameTooLong;
                }
                path_space.len = path_byte_len / 2;
                // Both prefixes will be normalized but retained, so all
                // we need to do now is replace them with the NT prefix
                path_space.data[0..nt_prefix.len].* = nt_prefix;
                return path_space;
            },
        };
        if (options.allow_relative and path_type == .relative) relative: {
            // TODO: Handle special case device names like COM1, AUX, NUL, CONIN$, CONOUT$, etc.
            //       See https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html

            // TODO: Potentially strip all trailing . and space characters from the
            //       end of the path. This is something that both RtlDosPathNameToNtPathName_U
            //       and RtlGetFullPathName_U do. Technically, trailing . and spaces
            //       are allowed, but such paths may not interact well with Windows (i.e.
            //       files with these paths can't be deleted from explorer.exe, etc).
            //       This could be something that normalizePath may want to do.

            @memcpy(path_space.data[0..path.len], path);
            // Try to normalize, but if we get too many parent directories,
            // then we need to start over and use RtlGetFullPathName_U instead.
            path_space.len = windows.normalizePath(u16, path_space.data[0..path.len]) catch |err| switch (err) {
                error.TooManyParentDirs => break :relative,
            };
            path_space.data[path_space.len] = 0;
            return path_space;
        }
        // We now know we are going to return an absolute NT path, so
        // we can unconditionally prefix it with the NT prefix.
        path_space.data[0..nt_prefix.len].* = nt_prefix;
        if (path_type == .root_local_device) {
            // `\\.` and `\\?` always get converted to `\??\` exactly, so
            // we can just stop here
            path_space.len = nt_prefix.len;
            path_space.data[path_space.len] = 0;
            return path_space;
        }
        const path_buf_offset = switch (path_type) {
            // UNC paths will always start with `\\`. However, we want to
            // end up with something like `\??\UNC\server\share`, so to get
            // RtlGetFullPathName to write into the spot we want the `server`
            // part to end up, we need to provide an offset such that
            // the `\\` part gets written where the `C\` of `UNC\` will be
            // in the final NT path.
            .unc_absolute => nt_prefix.len + 2,
            else => nt_prefix.len,
        };
        const buf_len: u32 = @intCast(path_space.data.len - path_buf_offset);
        const path_to_get: [:0]const u16 = path_to_get: {
            // If dir is null, then we don't need to bother with GetFinalPathNameByHandle because
            // RtlGetFullPathName_U will resolve relative paths against the CWD for us.
            if (path_type != .relative or dir == null) {
                break :path_to_get path;
            }
            // We can also skip GetFinalPathNameByHandle if the handle matches
            // the handle returned by Io.Dir.cwd()
            if (dir.? == Io.Dir.cwd().handle) {
                break :path_to_get path;
            }
            // At this point, we know we have a relative path that had too many
            // `..` components to be resolved by normalizePath, so we need to
            // convert it into an absolute path and let RtlGetFullPathName_U
            // canonicalize it. We do this by getting the path of the `dir`
            // and appending the relative path to it.
            var dir_path_buf: [windows.PATH_MAX_WIDE:0]u16 = undefined;
            const dir_path = GetFinalPathNameByHandle(dir.?, .{}, &dir_path_buf) catch |err| switch (err) {
                // This mapping is not correct; it is actually expected
                // that calling GetFinalPathNameByHandle might return
                // error.UnrecognizedVolume, and in fact has been observed
                // in the wild. The problem is that wToPrefixedFileW was
                // never intended to make *any* OS syscall APIs. It's only
                // supposed to convert a string to one that is eligible to
                // be used in the ntdll syscalls.
                //
                // To solve this, this function needs to no longer call
                // GetFinalPathNameByHandle under any conditions, or the
                // calling function needs to get reworked to not need to
                // call this function.
                //
                // This may involve making breaking API changes.
                error.UnrecognizedVolume => return error.Unexpected,
                else => |e| return e,
            };
            if (dir_path.len + 1 + path.len > windows.PATH_MAX_WIDE) {
                return error.NameTooLong;
            }
            // We don't have to worry about potentially doubling up path separators
            // here since RtlGetFullPathName_U will handle canonicalizing it.
            dir_path_buf[dir_path.len] = '\\';
            @memcpy(dir_path_buf[dir_path.len + 1 ..][0..path.len], path);
            const full_len = dir_path.len + 1 + path.len;
            dir_path_buf[full_len] = 0;
            break :path_to_get dir_path_buf[0..full_len :0];
        };
        const path_byte_len = windows.ntdll.RtlGetFullPathName_U(
            path_to_get.ptr,
            buf_len * 2,
            path_space.data[path_buf_offset..].ptr,
            null,
        );
        if (path_byte_len == 0) {
            // TODO: This may not be the right error
            return error.BadPathName;
        } else if (path_byte_len / 2 > buf_len) {
            return error.NameTooLong;
        }
        path_space.len = path_buf_offset + (path_byte_len / 2);
        if (path_type == .unc_absolute) {
            // Now add in the UNC, the `C` should overwrite the first `\` of the
            // FullPathName, ultimately resulting in `\??\UNC\<the rest of the path>`
            assert(path_space.data[path_buf_offset] == '\\');
            assert(path_space.data[path_buf_offset + 1] == '\\');
            const unc = [_]u16{ 'U', 'N', 'C' };
            path_space.data[nt_prefix.len..][0..unc.len].* = unc;
        }
        return path_space;
    }
}

pub const LocalDevicePathType = enum {
    /// `\\.\` (path separators can be `\` or `/`)
    local_device,
    /// `\\?\`
    /// When converted to an NT path, everything past the prefix is left
    /// untouched and `\\?\` is replaced by `\??\`.
    verbatim,
    /// `\\?\` without all path separators being `\`.
    /// This seems to be recognized as a prefix, but the 'verbatim' aspect
    /// is not respected (i.e. if `//?/C:/foo` is converted to an NT path,
    /// it will become `\??\C:\foo` [it will be canonicalized and the //?/ won't
    /// be treated as part of the final path])
    fake_verbatim,
};

/// Only relevant for Win32 -> NT path conversion.
/// Asserts `path` is of type `Dir.path.Win32PathType.local_device`.
pub fn getLocalDevicePathType(comptime T: type, path: []const T) LocalDevicePathType {
    if (std.debug.runtime_safety) {
        assert(Dir.path.getWin32PathType(T, path) == .local_device);
    }

    const backslash = std.mem.nativeToLittle(T, '\\');
    const all_backslash = path[0] == backslash and
        path[1] == backslash and
        path[3] == backslash;
    return switch (path[2]) {
        std.mem.nativeToLittle(T, '?') => if (all_backslash) .verbatim else .fake_verbatim,
        std.mem.nativeToLittle(T, '.') => .local_device,
        else => unreachable,
    };
}

/// Same as `wToPrefixedFileW` but accepts a WTF-8 encoded path.
/// https://wtf-8.codeberg.page/
pub fn sliceToPrefixedFileW(dir: ?windows.HANDLE, path: []const u8, options: Wtf16ToPrefixedFileWOptions) Wtf8ToPrefixedFileWError!WindowsPathSpace {
    var temp_path: WindowsPathSpace = undefined;
    temp_path.len = std.unicode.wtf8ToWtf16Le(&temp_path.data, path) catch |err| switch (err) {
        error.InvalidWtf8 => return error.BadPathName,
    };
    temp_path.data[temp_path.len] = 0;
    return wToPrefixedFileW(dir, temp_path.span(), options);
}

pub const WindowsPathSpace = struct {
    data: [windows.PATH_MAX_WIDE:0]u16,
    len: usize,

    pub fn span(wps: *const WindowsPathSpace) [:0]const u16 {
        return wps.data[0..wps.len :0];
    }

    pub fn string(wps: *const WindowsPathSpace) windows.UNICODE_STRING {
        return .init(wps.span());
    }
};

pub fn dirRealPathWindows(userdata: ?*anyopaque, dir: Dir, out_buffer: []u8) Dir.RealPathError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathWindows(dir.handle, out_buffer);
}

pub fn fileRealPathWindows(userdata: ?*anyopaque, file: File, out_buffer: []u8) File.RealPathError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathWindows(file.handle, out_buffer);
}

pub fn dirDeleteFileWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteFileError!void {
    return dirDeleteWindows(userdata, dir, sub_path, false) catch |err| switch (err) {
        error.DirNotEmpty => unreachable,
        else => |e| return e,
    };
}

pub fn dirDeleteDirWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteDirError!void {
    return dirDeleteWindows(userdata, dir, sub_path, true) catch |err| switch (err) {
        error.IsDir => unreachable,
        else => |e| return e,
    };
}

pub fn dirDeleteWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, remove_dir: bool) (Dir.DeleteDirError || Dir.DeleteFileError)!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const w = windows;

    if (std.mem.eql(u8, sub_path, "..")) {
        // Can't remove the parent directory with an open handle.
        return error.FileBusy;
    }
    var sub_path_w = try sliceToPrefixedFileW(dir.handle, sub_path, .{});
    if (std.mem.eql(u8, sub_path, ".")) {
        // Windows does not recognize this, but it does work with empty string.
        sub_path_w.len = 0;
    }
    const attr: w.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w.span())) null else dir.handle,
        .ObjectName = @constCast(&sub_path_w.string()),
    };

    var io_status_block: w.IO_STATUS_BLOCK = undefined;
    var tmp_handle: w.HANDLE = undefined;
    {
        const syscall: Syscall = try .start();
        while (true) switch (w.ntdll.NtCreateFile(
            &tmp_handle,
            .{ .STANDARD = .{
                .RIGHTS = .{ .DELETE = true },
                .SYNCHRONIZE = true,
            } },
            &attr,
            &io_status_block,
            null,
            .{},
            .VALID_FLAGS,
            .OPEN,
            .{
                .DIRECTORY_FILE = remove_dir,
                .IO = .SYNCHRONOUS_NONALERT,
                .NON_DIRECTORY_FILE = !remove_dir,
                .OPEN_REPARSE_POINT = true, // would we ever want to delete the target instead?
            },
            null,
            0,
        )) {
            .SUCCESS => break syscall.finish(),
            .OBJECT_NAME_INVALID => |err| return syscall.ntstatusBug(err),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .BAD_NETWORK_PATH => return syscall.fail(error.NetworkNotFound), // \\server was not found
            .BAD_NETWORK_NAME => return syscall.fail(error.NetworkNotFound), // \\server was found but \\server\share wasn't
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .FILE_IS_A_DIRECTORY => return syscall.fail(error.IsDir),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .SHARING_VIOLATION => return syscall.fail(error.FileBusy),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .DELETE_PENDING => return syscall.finish(),
            else => |rc| return syscall.unexpectedNtstatus(rc),
        };
    }
    defer w.CloseHandle(tmp_handle);

    // FileDispositionInformationEx has varying levels of support:
    // - FILE_DISPOSITION_INFORMATION_EX requires >= win10_rs1
    //   (INVALID_INFO_CLASS is returned if not supported)
    // - Requires the NTFS filesystem
    //   (on filesystems like FAT32, INVALID_PARAMETER is returned)
    // - FILE_DISPOSITION_POSIX_SEMANTICS requires >= win10_rs1
    // - FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE requires >= win10_rs5
    //   (NOT_SUPPORTED is returned if a flag is unsupported)
    //
    // The strategy here is just to try using FileDispositionInformationEx and fall back to
    // FileDispositionInformation if the return value lets us know that some aspect of it is not supported.
    const rc = rc: {
        // Deletion with posix semantics if the filesystem supports it.
        var info: w.FILE.DISPOSITION.INFORMATION.EX = .{ .Flags = .{
            .DELETE = true,
            .POSIX_SEMANTICS = true,
            .IGNORE_READONLY_ATTRIBUTE = true,
        } };

        const syscall: Syscall = try .start();
        while (true) switch (w.ntdll.NtSetInformationFile(
            tmp_handle,
            &io_status_block,
            &info,
            @sizeOf(w.FILE.DISPOSITION.INFORMATION.EX),
            .DispositionEx,
        )) {
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            // The filesystem does not support FileDispositionInformationEx
            .INVALID_PARAMETER,
            // The operating system does not support FileDispositionInformationEx
            .INVALID_INFO_CLASS,
            // The operating system does not support one of the flags
            .NOT_SUPPORTED,
            => break, // use fallback path below; `syscall` still active

            // For all other statuses, fall down to the switch below to handle them.
            else => |rc| {
                syscall.finish();
                break :rc rc;
            },
        };

        // Deletion with file pending semantics, which requires waiting or moving
        // files to get them removed (from here).
        var file_dispo: w.FILE.DISPOSITION.INFORMATION = .{ .DeleteFile = .TRUE };

        while (true) switch (w.ntdll.NtSetInformationFile(
            tmp_handle,
            &io_status_block,
            &file_dispo,
            @sizeOf(w.FILE.DISPOSITION.INFORMATION),
            .Disposition,
        )) {
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |rc| {
                syscall.finish();
                break :rc rc;
            },
        };
    };
    switch (rc) {
        .SUCCESS => {},
        .DIRECTORY_NOT_EMPTY => return error.DirNotEmpty,
        .INVALID_PARAMETER => |err| return w.statusBug(err),
        .CANNOT_DELETE => return error.AccessDenied,
        .MEDIA_WRITE_PROTECTED => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        else => return w.unexpectedStatus(rc),
    }
}

pub fn dirRenameWindows(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenameError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return dirRenameWindowsInner(old_dir, old_sub_path, new_dir, new_sub_path, true) catch |err| switch (err) {
        error.PathAlreadyExists => return error.Unexpected,
        error.OperationUnsupported => return error.Unexpected,
        else => |e| return e,
    };
}

pub fn dirRenameWindowsInner(
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
    replace_if_exists: bool,
) Dir.RenamePreserveError!void {
    const w = windows;
    const old_path_w_buf = try sliceToPrefixedFileW(old_dir.handle, old_sub_path, .{});
    const old_path_w = old_path_w_buf.span();
    const new_path_w_buf = try sliceToPrefixedFileW(new_dir.handle, new_sub_path, .{});
    const new_path_w = new_path_w_buf.span();

    const src_fd = src_fd: {
        if (OpenFile(old_path_w, .{
            .dir = old_dir.handle,
            .access_mask = .{
                .GENERIC = .{ .WRITE = true },
                .STANDARD = .{
                    .RIGHTS = .{ .DELETE = true },
                    .SYNCHRONIZE = true,
                },
            },
            .creation = .OPEN,
            .filter = .any, // This function is supposed to rename both files and directories.
            .follow_symlinks = false,
        })) |handle| {
            break :src_fd handle;
        } else |err| switch (err) {
            error.WouldBlock => unreachable, // Not possible without `.share_access_nonblocking = true`.
            else => |e| return e,
        }
    };
    defer w.CloseHandle(src_fd);

    var rc: w.NTSTATUS = undefined;
    var attempt: u5 = 0;

    // FileRenameInformationEx has varying levels of support:
    // - FILE_RENAME_INFORMATION_EX requires >= win10_rs1
    //   (INVALID_INFO_CLASS is returned if not supported)
    // - Requires the NTFS filesystem
    //   (on filesystems like FAT32, INVALID_PARAMETER is returned)
    // - FILE_RENAME_POSIX_SEMANTICS requires >= win10_rs1
    // - FILE_RENAME_IGNORE_READONLY_ATTRIBUTE requires >= win10_rs5
    //   (NOT_SUPPORTED is returned if a flag is unsupported)
    //
    // The strategy here is just to try using FileRenameInformationEx and fall back to
    // FileRenameInformation if the return value lets us know that some aspect of it is not supported.
    const need_fallback = need_fallback: {
        var rename_info: w.FILE.RENAME_INFORMATION = .init(.{
            .Flags = .{
                .REPLACE_IF_EXISTS = replace_if_exists,
                .POSIX_SEMANTICS = true,
                .IGNORE_READONLY_ATTRIBUTE = true,
            },
            .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(new_path_w)) null else new_dir.handle,
            .FileName = new_path_w,
        });
        var io_status_block: w.IO_STATUS_BLOCK = undefined;
        const rename_info_buf = rename_info.toBuffer();
        var syscall: Syscall = try .start();
        while (true) {
            rc = w.ntdll.NtSetInformationFile(
                src_fd,
                &io_status_block,
                rename_info_buf.ptr,
                @intCast(rename_info_buf.len),
                .RenameEx,
            );
            switch (rc) {
                // For all other statuses, fall down to the switch below to handle them.
                else => {
                    syscall.finish();
                    break :need_fallback false;
                },
                .CANCELLED => try syscall.checkCancel(),
                // The filesystem does not support FileDispositionInformationEx
                .INVALID_PARAMETER,
                // The operating system does not support FileDispositionInformationEx
                .INVALID_INFO_CLASS,
                // The operating system does not support one of the flags
                .NOT_SUPPORTED,
                => {
                    syscall.finish();
                    break :need_fallback true;
                },
                .ACCESS_DENIED => {
                    syscall.finish();
                    if (max_windows_kernel_bug_retries - attempt == 0) break :need_fallback false;
                    try parking_sleep.sleep(.{ .duration = .{
                        .raw = .fromMilliseconds((@as(u32, 1) << attempt) >> 1),
                        .clock = .awake,
                    } });
                    attempt += 1;
                    syscall = try .start();
                },
            }
        }
    };

    if (need_fallback) {
        var rename_info: w.FILE.RENAME_INFORMATION = .init(.{
            .Flags = .{ .REPLACE_IF_EXISTS = replace_if_exists },
            .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(new_path_w)) null else new_dir.handle,
            .FileName = new_path_w,
        });
        var io_status_block: w.IO_STATUS_BLOCK = undefined;
        const rename_info_buf = rename_info.toBuffer();
        var syscall: Syscall = try .start();
        while (true) {
            rc = w.ntdll.NtSetInformationFile(
                src_fd,
                &io_status_block,
                rename_info_buf.ptr,
                @intCast(rename_info_buf.len),
                .Rename,
            );
            switch (rc) {
                else => {
                    syscall.finish();
                    break;
                },
                .CANCELLED => try syscall.checkCancel(),
                .ACCESS_DENIED => {
                    syscall.finish();
                    if (max_windows_kernel_bug_retries - attempt == 0) break;
                    try parking_sleep.sleep(.{ .duration = .{
                        .raw = .fromMilliseconds((@as(u32, 1) << attempt) >> 1),
                        .clock = .awake,
                    } });
                    attempt += 1;
                    syscall = try .start();
                },
            }
        }
    }

    switch (rc) {
        .SUCCESS => {},
        .INVALID_HANDLE => |err| return w.statusBug(err),
        .INVALID_PARAMETER => |err| return w.statusBug(err),
        .OBJECT_PATH_SYNTAX_BAD => |err| return w.statusBug(err),
        .ACCESS_DENIED => return error.AccessDenied,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NOT_SAME_DEVICE => return error.CrossDevice,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .DIRECTORY_NOT_EMPTY => return error.DirNotEmpty,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        else => return w.unexpectedStatus(rc),
    }
}

pub fn dirSymLinkWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: Dir.SymLinkFlags,
) Dir.SymLinkError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const w = windows;

    // Target path does not use sliceToPrefixedFileW because certain paths
    // are handled differently when creating a symlink than they would be
    // when converting to an NT namespaced path.
    var target_path_w: WindowsPathSpace = undefined;
    target_path_w.len = try w.wtf8ToWtf16Le(&target_path_w.data, target_path);
    target_path_w.data[target_path_w.len] = 0;
    // However, we need to canonicalize any path separators to `\`, since if
    // the target path is relative, then it must use `\` as the path separator.
    std.mem.replaceScalar(
        u16,
        target_path_w.data[0..target_path_w.len],
        std.mem.nativeToLittle(u16, '/'),
        std.mem.nativeToLittle(u16, '\\'),
    );

    const sym_link_path_w = try sliceToPrefixedFileW(dir.handle, sym_link_path, .{});

    const SYMLINK_DATA = extern struct {
        ReparseTag: w.IO_REPARSE_TAG,
        ReparseDataLength: w.USHORT,
        Reserved: w.USHORT,
        SubstituteNameOffset: w.USHORT,
        SubstituteNameLength: w.USHORT,
        PrintNameOffset: w.USHORT,
        PrintNameLength: w.USHORT,
        Flags: w.ULONG,
    };

    const symlink_handle = handle: {
        if (OpenFile(sym_link_path_w.span(), .{
            .access_mask = .{
                .GENERIC = .{ .READ = true, .WRITE = true },
                .STANDARD = .{ .SYNCHRONIZE = true },
            },
            .dir = dir.handle,
            .creation = .CREATE,
            .filter = if (flags.is_directory) .dir_only else .non_directory_only,
        })) |handle| {
            break :handle handle;
        } else |err| switch (err) {
            error.IsDir => return error.PathAlreadyExists,
            error.NotDir => return error.Unexpected,
            error.WouldBlock => return error.Unexpected,
            error.PipeBusy => return error.Unexpected,
            error.FileBusy => return error.Unexpected,
            error.NoDevice => return error.Unexpected,
            error.AntivirusInterference => return error.Unexpected,
            else => |e| return e,
        }
    };
    defer w.CloseHandle(symlink_handle);

    // Relevant portions of the documentation:
    // > Relative links are specified using the following conventions:
    // > - Root relative—for example, "\Windows\System32" resolves to "current drive:\Windows\System32".
    // > - Current working directory–relative—for example, if the current working directory is
    // >   C:\Windows\System32, "C:File.txt" resolves to "C:\Windows\System32\File.txt".
    // > Note: If you specify a current working directory–relative link, it is created as an absolute
    // > link, due to the way the current working directory is processed based on the user and the thread.
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsymboliclinkw
    var is_target_absolute = false;
    const final_target_path = target_path: {
        if (w.hasCommonNtPrefix(u16, target_path_w.span())) {
            // Already an NT path, no need to do anything to it
            break :target_path target_path_w.span();
        } else {
            switch (Dir.path.getWin32PathType(u16, target_path_w.span())) {
                // Rooted paths need to avoid getting put through wToPrefixedFileW
                // (and they are treated as relative in this context)
                // Note: It seems that rooted paths in symbolic links are relative to
                //       the drive that the symbolic exists on, not to the CWD's drive.
                //       So, if the symlink is on C:\ and the CWD is on D:\,
                //       it will still resolve the path relative to the root of
                //       the C:\ drive.
                .rooted => break :target_path target_path_w.span(),
                // Keep relative paths relative, but anything else needs to get NT-prefixed.
                else => if (!Dir.path.isAbsoluteWindowsWtf16(target_path_w.span()))
                    break :target_path target_path_w.span(),
            }
        }
        var prefixed_target_path = try wToPrefixedFileW(dir.handle, target_path_w.span(), .{});
        // We do this after prefixing to ensure that drive-relative paths are treated as absolute
        is_target_absolute = Dir.path.isAbsoluteWindowsWtf16(prefixed_target_path.span());
        break :target_path prefixed_target_path.span();
    };

    // prepare reparse data buffer
    var buffer: [w.MAXIMUM_REPARSE_DATA_BUFFER_SIZE]u8 = undefined;
    const buf_len = @sizeOf(SYMLINK_DATA) + final_target_path.len * 4;
    const header_len = @sizeOf(w.ULONG) + @sizeOf(w.USHORT) * 2;
    const target_is_absolute = Dir.path.isAbsoluteWindowsWtf16(final_target_path);
    const symlink_data: SYMLINK_DATA = .{
        .ReparseTag = .SYMLINK,
        .ReparseDataLength = @intCast(buf_len - header_len),
        .Reserved = 0,
        .SubstituteNameOffset = @intCast(final_target_path.len * 2),
        .SubstituteNameLength = @intCast(final_target_path.len * 2),
        .PrintNameOffset = 0,
        .PrintNameLength = @intCast(final_target_path.len * 2),
        .Flags = if (!target_is_absolute) w.SYMLINK_FLAG_RELATIVE else 0,
    };

    @memcpy(buffer[0..@sizeOf(SYMLINK_DATA)], std.mem.asBytes(&symlink_data));
    @memcpy(buffer[@sizeOf(SYMLINK_DATA)..][0 .. final_target_path.len * 2], @as([*]const u8, @ptrCast(final_target_path)));
    const paths_start = @sizeOf(SYMLINK_DATA) + final_target_path.len * 2;
    @memcpy(buffer[paths_start..][0 .. final_target_path.len * 2], @as([*]const u8, @ptrCast(final_target_path)));
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = symlink_handle, .flags = .{ .nonblocking = false } },
        .code = .SET_REPARSE_POINT,
        .in = buffer[0..buf_len],
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .PRIVILEGE_NOT_HELD => return error.PermissionDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_DEVICE_REQUEST => return error.FileSystem,
        else => |status| return w.unexpectedStatus(status),
    }
}

pub fn dirReadLinkWindows(dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    // This gets used once for `sub_path` and then reused again temporarily
    // before converting back to `buffer`.
    var sub_path_w = try sliceToPrefixedFileW(dir.handle, sub_path, .{});
    const attr: windows.OBJECT.ATTRIBUTES = .{
        .RootDirectory = if (Dir.path.isAbsoluteWindowsWtf16(sub_path_w.span())) null else dir.handle,
        .ObjectName = @constCast(&sub_path_w.string()),
    };
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var result_handle: windows.HANDLE = undefined;
    var attempt: u5 = 0;
    var syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtCreateFile(
        &result_handle,
        .{
            .SPECIFIC = .{ .FILE = .{
                .READ_ATTRIBUTES = true,
            } },
            .STANDARD = .{ .SYNCHRONIZE = true },
        },
        &attr,
        &io_status_block,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS,
        .OPEN,
        .{
            .DIRECTORY_FILE = false,
            .NON_DIRECTORY_FILE = false,
            .IO = .SYNCHRONOUS_NONALERT,
            .OPEN_REPARSE_POINT = true,
        },
        null,
        0,
    )) {
        .SUCCESS => {
            syscall.finish();
            break;
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
            if (max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
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
            // call has failed. Here, we simulate the kernel bug being
            // fixed by sleeping and retrying until the error goes away.
            syscall.finish();
            if (max_windows_kernel_bug_retries - attempt == 0) return error.FileBusy;
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
        .NO_MEDIA_IN_DEVICE => return syscall.fail(error.FileNotFound),
        .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
        .PIPE_BUSY => return syscall.fail(error.AccessDenied),
        .PIPE_NOT_AVAILABLE => return syscall.fail(error.FileNotFound),
        .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
        .VIRUS_INFECTED, .VIRUS_DELETED => return syscall.fail(error.AntivirusInterference),
        .INVALID_PARAMETER => |status| return syscall.ntstatusBug(status),
        .OBJECT_PATH_SYNTAX_BAD => |status| return syscall.ntstatusBug(status),
        .INVALID_HANDLE => |status| return syscall.ntstatusBug(status),
        else => |status| return syscall.unexpectedNtstatus(status),
    };
    defer windows.CloseHandle(result_handle);

    var reparse_buf: [windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE]u8 align(@alignOf(windows.REPARSE_DATA_BUFFER)) = undefined;
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = result_handle, .flags = .{ .nonblocking = false } },
        .code = .GET_REPARSE_POINT,
        .out = &reparse_buf,
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .NOT_A_REPARSE_POINT => return error.NotLink,
        else => |status| return windows.unexpectedStatus(status),
    }

    const reparse_struct: *const windows.REPARSE_DATA_BUFFER = @ptrCast(@alignCast(&reparse_buf));
    const IoReparseTagInt = @typeInfo(windows.IO_REPARSE_TAG).@"struct".backing_integer.?;
    const result_w = switch (@as(IoReparseTagInt, @bitCast(reparse_struct.ReparseTag))) {
        @as(IoReparseTagInt, @bitCast(windows.IO_REPARSE_TAG.SYMLINK)) => r: {
            const buf: *const windows.SYMBOLIC_LINK_REPARSE_BUFFER = @ptrCast(@alignCast(&reparse_struct.DataBuffer[0]));
            const offset = buf.SubstituteNameOffset >> 1;
            const len = buf.SubstituteNameLength >> 1;
            const path_buf = @as([*]const u16, &buf.PathBuffer);
            const is_relative = buf.Flags & windows.SYMLINK_FLAG_RELATIVE != 0;
            break :r try parseReadLinkPath(path_buf[offset..][0..len], is_relative, &sub_path_w.data);
        },
        @as(IoReparseTagInt, @bitCast(windows.IO_REPARSE_TAG.MOUNT_POINT)) => r: {
            const buf: *const windows.MOUNT_POINT_REPARSE_BUFFER = @ptrCast(@alignCast(&reparse_struct.DataBuffer[0]));
            const offset = buf.SubstituteNameOffset >> 1;
            const len = buf.SubstituteNameLength >> 1;
            const path_buf = @as([*]const u16, &buf.PathBuffer);
            break :r try parseReadLinkPath(path_buf[offset..][0..len], false, &sub_path_w.data);
        },
        else => return error.UnsupportedReparsePointType,
    };
    const len = std.unicode.calcWtf8Len(result_w);
    if (len > buffer.len) return error.NameTooLong;

    return std.unicode.wtf16LeToWtf8(buffer, result_w);
}

pub fn parseReadLinkPath(path: []const u16, is_relative: bool, out_buffer: []u16) error{NameTooLong}![]u16 {
    path: {
        if (is_relative) break :path;
        return windows.ntToWin32Namespace(path, out_buffer) catch |err| switch (err) {
            error.NameTooLong => |e| return e,
            error.NotNtPath => break :path,
        };
    }
    if (out_buffer.len < path.len) return error.NameTooLong;
    const dest = out_buffer[0..path.len];
    @memcpy(dest, path);
    return dest;
}

pub fn dirSetPermissionsWindows(userdata: ?*anyopaque, dir: Dir, permissions: Dir.Permissions) Dir.SetPermissionsError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = dir;
    _ = permissions;
    @panic("TODO implement dirSetPermissionsWindows");
}

pub fn fileSyncWindows(userdata: ?*anyopaque, file: File) File.SyncError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    const syscall: Syscall = try .start();
    while (true) {
        switch (windows.ntdll.NtFlushBuffersFile(file.handle, &io_status_block)) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INVALID_HANDLE => unreachable,
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied), // a sync was performed but the system couldn't update the access time
            .UNEXPECTED_NETWORK_ERROR => return syscall.fail(error.InputOutput),
            else => |status| return syscall.unexpectedNtstatus(status),
        }
    }
}

pub fn fileReadStreamingWindows(file: File, data: []const []u8) File.ReadStreamingError!usize {
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    var index: usize = 0;
    while (data.len - index != 0 and data[index].len == 0) index += 1;
    if (data.len - index == 0) return 0;
    const buffer = data[index];
    const short_buffer_len = std.math.lossyCast(u32, buffer.len);
    if (file.flags.nonblocking) {
        var done: bool = false;
        switch (windows.ntdll.NtReadFile(
            file.handle,
            null, // event
            flagApc,
            &done, // APC context
            &iosb,
            buffer.ptr,
            short_buffer_len,
            null, // byte offset
            null, // key
        )) {
            // We must wait for the APC routine.
            .PENDING, .SUCCESS => while (!done) {
                // Once we get here we must not return from the function until the
                // operation completes, thereby releasing reference to the iosb.
                const alertable_syscall = AlertableSyscall.start() catch |err| switch (err) {
                    error.Canceled => |e| {
                        var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
                        _ = windows.ntdll.NtCancelIoFileEx(file.handle, &iosb, &cancel_iosb);
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
        while (true) switch (windows.ntdll.NtReadFile(
            file.handle,
            null, // event
            null, // APC routine
            null, // APC context
            &iosb,
            buffer.ptr,
            short_buffer_len,
            null, // byte offset
            null, // key
        )) {
            .PENDING => unreachable, // unrecoverable: wrong File nonblocking flag
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
    return ntReadFileResult(&iosb);
}

pub fn ntReadFileResult(io_status_block: *const windows.IO_STATUS_BLOCK) !usize {
    switch (io_status_block.u.Status) {
        .PENDING => unreachable,
        .CANCELLED => unreachable,
        .SUCCESS => return io_status_block.Information,
        .END_OF_FILE, .PIPE_BROKEN, .PIPE_CLOSING => return error.EndOfStream,
        .INVALID_HANDLE => return error.NotOpenForReading,
        .INVALID_DEVICE_REQUEST => return error.IsDir,
        .FILE_LOCK_CONFLICT => return error.LockViolation,
        .ACCESS_DENIED => return error.AccessDenied,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn ntWriteFileResult(io_status_block: *const windows.IO_STATUS_BLOCK) !usize {
    switch (io_status_block.u.Status) {
        .PENDING => unreachable,
        .CANCELLED => unreachable,
        .SUCCESS => return io_status_block.Information,
        .INVALID_USER_BUFFER => return error.SystemResources,
        .NO_MEMORY => return error.SystemResources,
        .QUOTA_EXCEEDED => return error.SystemResources,
        .PIPE_BROKEN, .PIPE_CLOSING => return error.BrokenPipe,
        .INVALID_HANDLE => return error.NotOpenForWriting,
        .FILE_LOCK_CONFLICT => return error.LockViolation,
        .ACCESS_DENIED => return error.AccessDenied,
        .WORKING_SET_QUOTA => return error.SystemResources,
        .DISK_FULL => return error.NoSpaceLeft,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn fileReadPositionalWindows(file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
    var index: usize = 0;
    while (index < data.len and data[index].len == 0) index += 1;
    if (index == data.len) return 0;
    const buffer = data[index];

    return readFilePositionalWindows(file, buffer, offset);
}

pub fn readFilePositionalWindows(file: File, buffer: []u8, offset: u64) File.ReadPositionalError!usize {
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    const short_buffer_len = std.math.lossyCast(u32, buffer.len);
    const signed_offset: windows.LARGE_INTEGER = @intCast(offset);
    if (file.flags.nonblocking) {
        var done: bool = false;
        switch (windows.ntdll.NtReadFile(
            file.handle,
            null, // event
            flagApc,
            &done, // APC context
            &iosb,
            buffer.ptr,
            short_buffer_len,
            &signed_offset,
            null, // key
        )) {
            // We must wait for the APC routine.
            .PENDING, .SUCCESS => while (!done) {
                // Once we get here we must not return from the function until the
                // operation completes, thereby releasing reference to the iosb.
                const alertable_syscall = AlertableSyscall.start() catch |err| switch (err) {
                    error.Canceled => |e| {
                        var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
                        _ = windows.ntdll.NtCancelIoFileEx(file.handle, &iosb, &cancel_iosb);
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
        while (true) switch (windows.ntdll.NtReadFile(
            file.handle,
            null, // event
            null, // APC routine
            null, // APC context
            &iosb,
            buffer.ptr,
            short_buffer_len,
            &signed_offset,
            null, // key
        )) {
            .PENDING => unreachable, // unrecoverable: wrong File nonblocking flag
            .CANCELLED => try syscall.checkCancel(),
            else => |status| {
                syscall.finish();
                iosb.u.Status = status;
                break;
            },
        };
    }
    return ntReadFileResult(&iosb) catch |err| switch (err) {
        error.EndOfStream => 0,
        else => |e| e,
    };
}

pub fn writeFilePositionalWindows(file: File, buffer: []const u8, offset: u64) File.WritePositionalError!usize {
    assert(buffer.len != 0);
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    const short_buffer_len = std.math.lossyCast(u32, buffer.len);
    const signed_offset: windows.LARGE_INTEGER = @intCast(offset);
    if (file.flags.nonblocking) {
        var done: bool = false;
        switch (windows.ntdll.NtWriteFile(
            file.handle,
            null, // event
            flagApc,
            &done, // APC context
            &iosb,
            buffer.ptr,
            short_buffer_len,
            &signed_offset,
            null, // key
        )) {
            // We must wait for the APC routine.
            .PENDING, .SUCCESS => while (!done) {
                // Once we get here we must not return from the function until the
                // operation completes, thereby releasing reference to the iosb.
                const alertable_syscall = AlertableSyscall.start() catch |err| switch (err) {
                    error.Canceled => |e| {
                        var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
                        _ = windows.ntdll.NtCancelIoFileEx(file.handle, &iosb, &cancel_iosb);
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
        while (true) switch (windows.ntdll.NtWriteFile(
            file.handle,
            null, // event
            null, // APC routine
            null, // APC context
            &iosb,
            buffer.ptr,
            short_buffer_len,
            &signed_offset,
            null, // key
        )) {
            .PENDING => unreachable, // unrecoverable: wrong File nonblocking flag
            .CANCELLED => try syscall.checkCancel(),
            else => |status| {
                syscall.finish();
                iosb.u.Status = status;
                return ntWriteFileResult(&iosb);
            },
        };
    }
    return ntWriteFileResult(&iosb);
}

pub fn fileWriteStreamingWindows(file: File, buffer: []const u8) File.Writer.Error!usize {
    assert(buffer.len != 0);
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    if (file.flags.nonblocking) {
        var done: bool = false;
        switch (windows.ntdll.NtWriteFile(
            file.handle,
            null, // event
            flagApc,
            &done, // APC context
            &iosb,
            buffer.ptr,
            @intCast(buffer.len),
            null, // byte offset
            null, // key
        )) {
            // We must wait for the APC routine.
            .PENDING, .SUCCESS => while (!done) {
                // Once we get here we must not return from the function until the
                // operation completes, thereby releasing reference to io_status_block.
                const alertable_syscall = AlertableSyscall.start() catch |err| switch (err) {
                    error.Canceled => |e| {
                        var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
                        _ = windows.ntdll.NtCancelIoFileEx(file.handle, &iosb, &cancel_iosb);
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
        while (true) switch (windows.ntdll.NtWriteFile(
            file.handle,
            null, // event
            null, // APC routine
            null, // APC context
            &iosb,
            buffer.ptr,
            @intCast(buffer.len),
            null, // byte offset
            null, // key
        )) {
            .PENDING => unreachable, // unrecoverable: wrong File nonblocking flag
            .CANCELLED => try syscall.checkCancel(),
            else => |status| {
                syscall.finish();
                iosb.u.Status = status;
                break;
            },
        };
    }
    return ntWriteFileResult(&iosb);
}

pub fn nowWindows(clock: Io.Clock) Io.Timestamp {
    switch (clock) {
        .real => {
            // RtlGetSystemTimePrecise() has a granularity of 100 nanoseconds
            // and uses the NTFS/Windows epoch, which is 1601-01-01.
            const epoch_ns = std.time.epoch.windows * std.time.ns_per_s;
            return .{ .nanoseconds = @as(i96, windows.ntdll.RtlGetSystemTimePrecise()) * 100 + epoch_ns };
        },
        .awake, .boot => {
            // We don't need to cache QPF as it's internally just a memory read to KUSER_SHARED_DATA
            // (a read-only page of info updated and mapped by the kernel to all processes):
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
            // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
            const qpf: u64 = qpf: {
                var qpf: windows.LARGE_INTEGER = undefined;
                assert(windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool());
                break :qpf @bitCast(qpf);
            };

            // QPC on windows doesn't fail on >= XP/2000 and includes time suspended.
            const qpc: u64 = qpc: {
                var qpc: windows.LARGE_INTEGER = undefined;
                assert(windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool());
                break :qpc @bitCast(qpc);
            };

            // 10Mhz (1 qpc tick every 100ns) is a common enough QPF value that we can optimize on it.
            // https://github.com/microsoft/STL/blob/785143a0c73f030238ef618890fd4d6ae2b3a3a0/stl/inc/chrono#L694-L701
            const common_qpf = 10_000_000;
            if (qpf == common_qpf) return .{ .nanoseconds = qpc * (std.time.ns_per_s / common_qpf) };

            // Convert to ns using fixed point.
            const scale = @as(u64, std.time.ns_per_s << 32) / @as(u32, @intCast(qpf));
            const result = (@as(u96, qpc) * scale) >> 32;
            return .{ .nanoseconds = @intCast(result) };
        },
        .cpu_process => {
            const handle = windows.GetCurrentProcess();
            var times: windows.KERNEL_USER_TIMES = undefined;

            // https://github.com/reactos/reactos/blob/master/ntoskrnl/ps/query.c#L442-L485
            if (windows.ntdll.NtQueryInformationProcess(
                handle,
                .Times,
                &times,
                @sizeOf(windows.KERNEL_USER_TIMES),
                null,
            ) != .SUCCESS) return .zero;

            const sum = @as(i96, times.UserTime) + @as(i96, times.KernelTime);
            return .{ .nanoseconds = sum * 100 };
        },
        .cpu_thread => {
            const handle = windows.GetCurrentThread();
            var times: windows.KERNEL_USER_TIMES = undefined;

            // https://github.com/reactos/reactos/blob/master/ntoskrnl/ps/query.c#L2971-L3019
            if (windows.ntdll.NtQueryInformationThread(
                handle,
                .Times,
                &times,
                @sizeOf(windows.KERNEL_USER_TIMES),
                null,
            ) != .SUCCESS) return .zero;

            const sum = @as(i96, times.UserTime) + @as(i96, times.KernelTime);
            return .{ .nanoseconds = sum * 100 };
        },
    }
}

pub fn netListenIpWindows(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.ListenOptions,
) IpAddress.ListenError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_handle = try openSocketAfd(family, .{ .mode = options.mode, .protocol = options.protocol });
    errdefer windows.CloseHandle(socket_handle);
    if (options.reuse_address) try setSocketOptionAfd(socket_handle, ws2_32.SOL.SOCKET, ws2_32.SO.REUSEADDR, true);
    const bound_address = try bindSocketIpAfd(socket_handle, address, .Passive);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.START_LISTEN,
        .in = @ptrCast(&windows.AFD.LISTEN_INFO{
            .UseSAN = .FALSE,
            .MaximumConnectionQueue = options.kernel_backlog,
            .UseDelayedAcceptance = .FALSE,
        }),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
    return .{ .handle = socket_handle, .address = bound_address };
}

pub fn netListenUnixWindows(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
    options: net.UnixAddress.ListenOptions,
) net.UnixAddress.ListenError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const is_abstract = address.isAbstract();
    const wps = if (!is_abstract) sliceToPrefixedFileW(null, address.path, .{
        .allow_relative = false,
    }) catch |err| switch (err) {
        error.NameTooLong, error.BadPathName => return error.AddressUnavailable,
        else => |e| return e,
    } else undefined;
    const socket_handle = openSocketAfd(ws2_32.AF.UNIX, .{ .mode = .stream }) catch |err| switch (err) {
        error.ProtocolUnsupportedByAddressFamily => return error.AddressFamilyUnsupported,
        else => |e| return e,
    };
    errdefer windows.CloseHandle(socket_handle);
    if (!is_abstract) try socketOptionAfd(socket_handle, .special, 0, ws2_32.SO.UNIX_PATH, @constCast(
        @as([]const u8, @ptrCast(&windows.AFD.SOCKOPT_INFO.UNIX_PATH{
            .Path = wps.data,
        }))[0 .. @offsetOf(windows.AFD.SOCKOPT_INFO.UNIX_PATH, "Path") + @sizeOf(windows.WCHAR) * wps.len],
    ));
    try bindSocketUnixAfd(socket_handle, address);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.START_LISTEN,
        .in = @ptrCast(&windows.AFD.LISTEN_INFO{
            .UseSAN = .FALSE,
            .MaximumConnectionQueue = options.kernel_backlog,
            .UseDelayedAcceptance = .FALSE,
        }),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
    return socket_handle;
}

pub fn setSocketOptionAfd(socket: net.Socket.Handle, level: i32, opt_name: u32, opt_val: anytype) !void {
    try socketOptionAfd(socket, .set, level, opt_name, @ptrCast(@constCast(&opt_val)));
}

pub fn socketOptionAfd(socket: net.Socket.Handle, mode: windows.AFD.SOCKOPT_INFO.Mode, level: i32, opt_name: u32, opt_val: []u8) !void {
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.SOCKOPT,
        .in = @ptrCast(&windows.AFD.SOCKOPT_INFO{
            .mode = mode,
            .level = level,
            .optname = opt_name,
            .optval = opt_val.ptr,
            .optlen = opt_val.len,
        }),
    })).u.Status) {
        .SUCCESS => return,
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn netConnectIpWindows(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.ConnectOptions,
) IpAddress.ConnectError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    if (options.timeout != .none) @panic("TODO implement netConnectIpWindows with timeout");
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_handle = try openSocketAfd(family, .{ .mode = options.mode, .protocol = options.protocol });
    errdefer windows.CloseHandle(socket_handle);
    try setSocketOptionAfd(socket_handle, ws2_32.SOL.SOCKET, ws2_32.SO.REUSE_UNICASTPORT, true);
    const bound_address = bindSocketIpAfd(socket_handle, &switch (address.*) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    }, .Active) catch |err| switch (err) {
        error.AddressInUse => return error.Unexpected,
        else => |e| return e,
    };
    const Storage = extern struct { Reserved0: [3]usize = @splat(0), Address: PosixAddress };
    var storage: Storage = .{ .Address = undefined };
    const addr_len = addressToPosix(address, &storage.Address);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.CONNECT,
        .in = @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(Storage, "Address") + addr_len],
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .CONNECTION_REFUSED => return error.ConnectionRefused,
        else => |status| return windows.unexpectedStatus(status),
    }
    return .{ .handle = socket_handle, .address = bound_address };
}

pub fn netConnectUnixWindows(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
) net.UnixAddress.ConnectError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const is_abstract = address.isAbstract();
    const wps = if (!is_abstract) sliceToPrefixedFileW(null, address.path, .{
        .allow_relative = false,
    }) catch |err| switch (err) {
        error.NameTooLong, error.BadPathName => return error.FileNotFound,
        else => |e| return e,
    } else undefined;
    const socket_handle = openSocketAfd(ws2_32.AF.UNIX, .{ .mode = .stream }) catch |err| switch (err) {
        error.ProtocolUnsupportedByAddressFamily => return error.AddressFamilyUnsupported,
        else => |e| return e,
    };
    errdefer windows.CloseHandle(socket_handle);
    if (!is_abstract) try socketOptionAfd(socket_handle, .special, 0, ws2_32.SO.UNIX_PATH, @constCast(
        @as([]const u8, @ptrCast(&windows.AFD.SOCKOPT_INFO.UNIX_PATH{
            .Path = wps.data,
        }))[0 .. @offsetOf(windows.AFD.SOCKOPT_INFO.UNIX_PATH, "Path") + @sizeOf(windows.WCHAR) * wps.len],
    ));
    bindSocketUnixAfd(socket_handle, &(net.UnixAddress.init("") catch |err| switch (err) {
        error.NameTooLong => unreachable,
    })) catch |err| switch (err) {
        error.AddressInUse => return error.Unexpected,
        else => |e| return e,
    };
    const Storage = extern struct { Reserved0: [3]usize = @splat(0), Address: UnixAddress };
    var storage: Storage = .{ .Address = undefined };
    const addr_len = addressUnixToPosix(address, &storage.Address);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.CONNECT,
        .in = @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(Storage, "Address") + addr_len],
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
    return socket_handle;
}

pub fn netBindIpWindows(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.BindOptions,
) IpAddress.BindError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_handle = try openSocketAfd(family, options);
    errdefer windows.CloseHandle(socket_handle);
    const bound_address = try bindSocketIpAfd(socket_handle, address, .Active);
    if (options.allow_broadcast) try setSocketOptionAfd(socket_handle, ws2_32.SOL.SOCKET, ws2_32.SO.BROADCAST, true);
    return .{ .handle = socket_handle, .address = bound_address };
}

pub fn openSocketAfd(family: ws2_32.ADDRESS_FAMILY, options: IpAddress.BindOptions) !net.Socket.Handle {
    const mode, const protocol = try posixSocketModeProtocol(family, options.mode, options.protocol);
    var handle: windows.HANDLE = undefined;
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    var syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtCreateFile(
        &handle,
        .{
            .STANDARD = .{ .RIGHTS = .{ .WRITE_DAC = true }, .SYNCHRONIZE = true },
            .GENERIC = .{ .WRITE = true, .READ = true },
        },
        &.{
            .ObjectName = @constCast(&windows.UNICODE_STRING.init(
                windows.AFD.DEVICE_NAME ++ .{ '\\', 'E', 'n', 'd', 'p', 'o', 'i', 'n', 't' },
            )),
        },
        &iosb,
        null,
        .{},
        .{ .READ = true, .WRITE = true },
        .OPEN_IF,
        .{ .IO = .ASYNCHRONOUS },
        &windows.AFD.OPEN_PACKET.FULL_EA_INFORMATION{ .Value = .{
            .EndpointType = .{
                .CONNECTIONLESS = switch (options.mode) {
                    .stream, .seqpacket, .rdm => false,
                    .dgram, .raw => true,
                },
                .MESSAGEMODE = options.mode != .stream,
                .RAW = options.mode == .raw,
            },
            .GroupID = 0,
            .AddressFamily = family,
            .SocketType = @bitCast(mode),
            .Protocol = @bitCast(protocol),
            .TransportDeviceNameLength = 0,
            .TransportDeviceName = undefined,
        } },
        @sizeOf(windows.AFD.OPEN_PACKET.FULL_EA_INFORMATION),
    )) {
        .SUCCESS => {
            syscall.finish();
            return handle;
        },
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .PROTOCOL_NOT_SUPPORTED => return syscall.fail(error.AddressFamilyUnsupported),
        .NO_SUCH_FILE => return syscall.fail(error.ProtocolUnsupportedByAddressFamily),
        else => |status| return syscall.unexpectedNtstatus(status),
    };
}

pub fn bindSocketIpAfd(socket_handle: net.Socket.Handle, address: *const IpAddress, mode: windows.AFD.BIND_INFO.MODE) !IpAddress {
    const Storage = extern struct { Info: windows.AFD.BIND_INFO, Address: PosixAddress };
    var storage: Storage = .{ .Info = .{ .Mode = mode }, .Address = undefined };
    const addr_len = addressToPosix(address, &storage.Address);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.BIND,
        .in = @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(Storage, "Address") + addr_len],
        .out = @as([]u8, @ptrCast(&storage.Address))[0..addr_len],
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .SHARING_VIOLATION => return error.AddressInUse,
        else => |status| return windows.unexpectedStatus(status),
    }
    return addressFromPosix(&storage.Address);
}

pub fn bindSocketUnixAfd(socket_handle: net.Socket.Handle, address: *const net.UnixAddress) !void {
    const Storage = extern struct { Info: windows.AFD.BIND_INFO, Address: UnixAddress };
    var storage: Storage = .{ .Info = .{ .Mode = .Unix }, .Address = undefined };
    const addr_len = addressUnixToPosix(address, &storage.Address);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.BIND,
        .in = @as([]const u8, @ptrCast(&storage))[0 .. @offsetOf(Storage, "Address") + addr_len],
        .out = @ptrCast(&storage.Address),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .ADDRESS_ALREADY_EXISTS => return error.AddressInUse,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn netAcceptWindows(userdata: ?*anyopaque, listen_handle: net.Socket.Handle, options: net.Server.AcceptOptions) net.Server.AcceptError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const Storage = extern struct {
        Info: windows.AFD.LISTEN_RESPONSE_INFO,
        RemoteAddress: extern union { posix: PosixAddress, unix: UnixAddress },
    };
    var storage: Storage = undefined;
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = listen_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.WAIT_FOR_LISTEN,
        .out = @ptrCast(&storage),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
    errdefer deferAcceptAfd(t, listen_handle, storage.Info);
    const accept_handle = openSocketAfd(
        storage.RemoteAddress.posix.any.family,
        .{ .mode = options.mode, .protocol = options.protocol },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported => return error.Unexpected,
        error.ProtocolUnsupportedByAddressFamily => return error.Unexpected,
        else => |e| return e,
    };
    errdefer windows.CloseHandle(accept_handle);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = listen_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.ACCEPT,
        .in = @ptrCast(&windows.AFD.ACCEPT_INFO{
            .UseSAN = .FALSE,
            .Sequence = storage.Info.Sequence,
            .AcceptHandle = accept_handle,
        }),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
    return .{ .handle = accept_handle, .address = addressFromPosix(&storage.RemoteAddress.posix) };
}

pub fn deferAcceptAfd(t: *Threaded, listen_handle: net.Socket.Handle, info: windows.AFD.LISTEN_RESPONSE_INFO) void {
    const cancel_protection = swapCancelProtection(t, .blocked);
    defer _ = swapCancelProtection(t, cancel_protection);
    switch ((deviceIoControl(&.{
        .file = .{ .handle = listen_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.DEFER_ACCEPT,
        .in = @ptrCast(&windows.AFD.DEFER_ACCEPT_INFO{
            .Sequence = info.Sequence,
            .Reject = .FALSE,
        }),
    }) catch |err| switch (err) {
        error.Canceled => unreachable, // blocked
    }).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        else => |status| windows.unexpectedStatus(status) catch {},
    }
}

pub fn netReadWindows(socket_handle: net.Socket.Handle, data: [][]u8) net.Stream.Reader.Error!usize {
    var iovecs: [max_iovecs_len]windows.AFD.WSABUF(.@"var") = undefined;
    var len: u32 = 0;
    for (data) |buf| {
        if (iovecs.len - len == 0) break;
        addAfdBuf(.@"var", &iovecs, &len, buf);
    }

    const iosb = try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.RECEIVE,
        .in = @ptrCast(&windows.AFD.RECV_INFO{
            .BufferArray = &iovecs,
            .BufferCount = len,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{ .NORMAL = true },
        }),
    });
    switch (iosb.u.Status) {
        .SUCCESS => return iosb.Information,
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .CONNECTION_RESET, .REMOTE_DISCONNECT, .LOCAL_DISCONNECT => return error.ConnectionResetByPeer,
        .IO_TIMEOUT => return error.ConnectionTimedOut,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn netSendWindows(
    t: *Threaded,
    socket_handle: net.Socket.Handle,
    messages: []net.OutgoingMessage,
    flags: net.SendFlags,
) struct { ?net.Socket.SendError, usize } {
    if (!have_networking) return .{ error.NetworkDown, 0 };
    for (messages, 0..) |*m, i| {
        netSendOneWindows(t, socket_handle, m, flags) catch |err| return .{ err, i };
    }
    return .{ null, messages.len };
}

pub fn netSendOneWindows(
    t: *Threaded,
    socket_handle: net.Socket.Handle,
    message: *net.OutgoingMessage,
    flags: net.SendFlags,
) net.Socket.SendError!void {
    _ = t;
    _ = flags;
    const iovecs: [1]windows.AFD.WSABUF(.@"const") = .{.{
        .buf = message.data_ptr,
        .len = std.math.cast(std.os.windows.ULONG, message.data_len) orelse
            return error.MessageOversize,
    }};
    var storage: PosixAddress = undefined;
    const addr_len = addressToPosix(message.address, &storage);
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.SEND_DATAGRAM,
        .in = @ptrCast(&windows.AFD.SEND_DATAGRAM_INFO{
            .BufferArray = &iovecs,
            .BufferCount = iovecs.len,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiRequest = undefined,
            .TdiConnInfo = .{
                .UserDataLength = undefined,
                .UserData = undefined,
                .OptionsLength = undefined,
                .Options = undefined,
                .RemoteAddressLength = @bitCast(addr_len),
                .RemoteAddress = &storage,
            },
        }),
    })).u.Status) {
        .SUCCESS => return,
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn netReceiveWindows(
    t: *Threaded,
    socket_handle: net.Socket.Handle,
    message_buffer: []net.IncomingMessage,
    data_buffer: []u8,
    flags: net.ReceiveFlags,
) struct { ?net.Socket.ReceiveError, usize } {
    netReceiveOneWindows(t, socket_handle, &message_buffer[0], data_buffer, flags) catch |err|
        return .{ err, 0 };
    return .{ null, 1 };
}

pub fn netReceiveOneWindows(
    t: *Threaded,
    socket_handle: net.Socket.Handle,
    message: *net.IncomingMessage,
    data_buffer: []u8,
    flags: net.ReceiveFlags,
) net.Socket.ReceiveError!void {
    if (!have_networking) return error.NetworkDown;
    _ = t;
    const iovecs: [1]windows.AFD.WSABUF(.@"var") = .{.{
        .buf = data_buffer.ptr,
        .len = std.math.cast(std.os.windows.ULONG, data_buffer.len) orelse return error.MessageOversize,
    }};
    var storage: PosixAddress = undefined;
    var addr_len: windows.ULONG = @sizeOf(PosixAddress);
    const iosb = try deviceIoControl(&.{
        .file = .{ .handle = socket_handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.RECEIVE_DATAGRAM,
        .in = @ptrCast(&windows.AFD.RECV_DATAGRAM_INFO{
            .BufferArray = &iovecs,
            .BufferCount = iovecs.len,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{ .NORMAL = !flags.oob, .EXPEDITED = flags.oob, .PEEK = flags.peek },
            .Address = &storage,
            .AddressLength = &addr_len,
        }),
    });
    switch (iosb.u.Status) {
        .SUCCESS, .RECEIVE_EXPEDITED => |status| message.* = .{
            .from = addressFromPosix(&storage),
            .data = data_buffer[0..iosb.Information],
            .control = &.{},
            .flags = .{
                .eor = false,
                .trunc = false,
                .ctrunc = false,
                .oob = switch (status) {
                    else => unreachable,
                    .SUCCESS, .RECEIVE_PARTIAL, .BUFFER_OVERFLOW => false,
                    .RECEIVE_EXPEDITED, .RECEIVE_PARTIAL_EXPEDITED => true,
                },
                .errqueue = false,
            },
        },
        .RECEIVE_PARTIAL,
        .RECEIVE_PARTIAL_EXPEDITED,
        => |status| return windows.unexpectedStatus(status), // TdiFlags.PARTIAL = false
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .BUFFER_OVERFLOW => return error.MessageOversize,
        .PORT_UNREACHABLE => return error.PortUnreachable,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn netWriteWindows(
    handle: net.Socket.Handle,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
    control: []const u8,
) net.Stream.Writer.Error!usize {
    if (!have_networking) return error.NetworkDown;

    // Windows doesn't have the concept of control/ancillary data.
    _ = control;

    var iovecs: [max_iovecs_len]windows.AFD.WSABUF(.@"const") = undefined;
    var len: u32 = 0;
    addAfdBuf(.@"const", &iovecs, &len, header);
    for (data[0 .. data.len - 1]) |bytes| addAfdBuf(.@"const", &iovecs, &len, bytes);
    const pattern = data[data.len - 1];
    var backup_buffer: [64]u8 = undefined;
    if (iovecs.len - len != 0) switch (splat) {
        0 => {},
        1 => addAfdBuf(.@"const", &iovecs, &len, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                const splat_buffer = &backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addAfdBuf(.@"const", &iovecs, &len, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and len < iovecs.len) {
                    addAfdBuf(.@"const", &iovecs, &len, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addAfdBuf(.@"const", &iovecs, &len, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - len)) |_| {
                addAfdBuf(.@"const", &iovecs, &len, pattern);
            },
        },
    };

    const iosb = try deviceIoControl(&.{
        .file = .{ .handle = handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.SEND,
        .in = @ptrCast(&windows.AFD.SEND_INFO{
            .BufferArray = &iovecs,
            .BufferCount = len,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{},
        }),
    });
    switch (iosb.u.Status) {
        .SUCCESS => return iosb.Information,
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .CONNECTION_RESET, .REMOTE_DISCONNECT, .LOCAL_DISCONNECT => return error.ConnectionResetByPeer,
        .IO_TIMEOUT => return error.ConnectionTimedOut,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn addAfdBuf(
    comptime mutability: windows.AFD.Mutability,
    iovecs: []windows.AFD.WSABUF(mutability),
    len: *u32,
    bytes: switch (mutability) {
        .@"const" => []const u8,
        .@"var" => []u8,
    },
) void {
    if (bytes.len == 0) return;
    const cap = std.math.maxInt(u32);
    var remaining = bytes;
    while (remaining.len > cap) {
        if (iovecs.len - len.* == 0) return;
        iovecs[len.*] = .{ .buf = remaining.ptr, .len = cap };
        len.* += 1;
        remaining = remaining[cap..];
    } else {
        @branchHint(.likely);
        if (iovecs.len - len.* == 0) return;
        iovecs[len.*] = .{ .buf = remaining.ptr, .len = @intCast(remaining.len) };
        len.* += 1;
    }
}

pub fn netShutdownWindows(userdata: ?*anyopaque, handle: net.Socket.Handle, how: net.ShutdownHow) net.ShutdownError!void {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    // shutdown does not support apcs at all
    switch ((try deviceIoControl(&.{
        .file = .{ .handle = handle, .flags = .{ .nonblocking = false } },
        .code = windows.IOCTL.AFD.PARTIAL_DISCONNECT,
        .in = @ptrCast(&windows.AFD.PARTIAL_DISCONNECT_INFO{
            .DisconnectMode = .{ .SEND = how != .recv, .RECEIVE = how != .send },
            .Timeout = -1,
        }),
    })).u.Status) {
        .SUCCESS => {},
        .CANCELLED => unreachable,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub const LookupDnsWindows = struct {
    threaded: *Threaded,
    thread: Thread.Handle,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
    results: windows.DNS.QUERY.RESULT,
    done: bool,

    pub fn completed(
        pQueryContext: ?*anyopaque,
        pQueryResults: *windows.DNS.QUERY.RESULT,
    ) callconv(.winapi) void {
        _ = pQueryContext;
        const lookup_dns: *LookupDnsWindows = @fieldParentPtr("results", pQueryResults);
        lookup_dns.completedFallible() catch |err| switch (err) {
            error.Closed => unreachable, // `resolved` must not be closed until `netLookup` returns
            error.Canceled => unreachable, // called from an uncancelable thread
        };
        @atomicStore(bool, &lookup_dns.done, true, .release);
        _ = windows.ntdll.NtAlertThread(lookup_dns.thread);
    }
    pub fn completedFallible(lookup_dns: *LookupDnsWindows) (Io.QueueClosedError || Io.Cancelable)!void {
        assert(!lookup_dns.done);
        const t = lookup_dns.threaded;
        defer t.dl.DnsFree.raw.?(lookup_dns.results.pQueryRecords, .RecordList);
        if (lookup_dns.results.QueryStatus != .SUCCESS) return;
        const t_io = t.io();
        var record_it = lookup_dns.results.pQueryRecords;
        while (record_it) |record| : (record_it = record.pNext) switch (record.wType) {
            else => {},
            .A => try lookup_dns.resolved.putOne(t_io, .{
                .address = .{ .ip4 = .{ .bytes = record.Data.A, .port = lookup_dns.options.port } },
            }),
            .AAAA => {
                const ip6: net.Ip6Address = .{
                    .bytes = record.Data.AAAA,
                    .port = lookup_dns.options.port,
                };
                try lookup_dns.resolved.putOne(t_io, .{
                    .address = if (lookup_dns.options.family) |_| .{ .ip6 = ip6 } else .fromIp6(ip6),
                });
            },
        };
        if (lookup_dns.results.pQueryRecords) |record| {
            if (lookup_dns.options.canonical_name_buffer) |buf| {
                const name_wtf16 = std.mem.span(
                    @as([*:0]const windows.WCHAR, @ptrCast(@alignCast(record.pName))),
                );
                const len = std.unicode.wtf16LeToWtf8(buf, name_wtf16);
                try lookup_dns.resolved.putOne(t_io, .{
                    .canonical_name = .{ .bytes = buf[0..len] },
                });
            }
        }
    }
};

pub const WindowsEnvironStrings = struct {
    PATH: ?[:0]const u16 = null,
    PATHEXT: ?[:0]const u16 = null,

    fn scan() WindowsEnvironStrings {
        const peb = windows.peb();
        assert(windows.ntdll.RtlEnterCriticalSection(peb.FastPebLock) == .SUCCESS);
        defer assert(windows.ntdll.RtlLeaveCriticalSection(peb.FastPebLock) == .SUCCESS);
        const ptr = peb.ProcessParameters.Environment;

        var result: WindowsEnvironStrings = .{};
        var i: usize = 0;
        while (ptr[i] != 0) {
            const key_start = i;

            // There are some special environment variables that start with =,
            // so we need a special case to not treat = as a key/value separator
            // if it's the first character.
            // https://devblogs.microsoft.com/oldnewthing/20100506-00/?p=14133
            if (ptr[key_start] == '=') i += 1;

            while (ptr[i] != 0 and ptr[i] != '=') : (i += 1) {}
            const key_w = ptr[key_start..i];

            if (ptr[i] == '=') i += 1;

            const value_start = i;
            while (ptr[i] != 0) : (i += 1) {}
            const value_w = ptr[value_start..i :0];

            i += 1; // skip over null byte

            inline for (@typeInfo(WindowsEnvironStrings).@"struct".field_names) |field_name| {
                const field_name_w = comptime std.unicode.wtf8ToWtf16LeStringLiteral(field_name);
                if (windows.eqlIgnoreCaseWtf16(key_w, field_name_w)) @field(result, field_name) = value_w;
            }
        }

        return result;
    }
};

pub fn childKillWindows(t: *Threaded, child: *process.Child, exit_code: windows.UINT) !void {
    _ = t; // TODO cancelation
    const handle = child.id.?;
    _ = windows.ntdll.RtlReportSilentProcessExit(handle, @fromBackingInt(@intCast(exit_code)));
    switch (windows.ntdll.NtTerminateProcess(handle, @fromBackingInt(@intCast(exit_code)))) {
        .SUCCESS, .PROCESS_IS_TERMINATING => {
            _ = windows.ntdll.NtWaitForSingleObject(handle, .FALSE, null);
            childCleanupWindows(child);
        },
        .ACCESS_DENIED => {
            // Usually when TerminateProcess triggers a ACCESS_DENIED error, it
            // indicates that the process has already exited, but there may be
            // some rare edge cases where our process handle no longer has the
            // PROCESS_TERMINATE access right, so let's do another check to make
            // sure the process is really no longer running:
            const minimal_timeout: windows.LARGE_INTEGER = -1;
            return switch (windows.ntdll.NtWaitForSingleObject(handle, .FALSE, &minimal_timeout)) {
                windows.NTSTATUS.WAIT_0 => error.AlreadyTerminated,
                else => error.AccessDenied,
            };
        },
        else => |status| return windows.unexpectedStatus(status),
    }
}

pub fn childWaitWindows(child: *process.Child) process.Child.WaitError!process.Child.Term {
    const handle = child.id.?;

    const alertable_syscall: AlertableSyscall = try .start();
    while (true) switch (windows.ntdll.NtWaitForSingleObject(handle, .TRUE, null)) {
        windows.NTSTATUS.WAIT_0 => break alertable_syscall.finish(),
        .USER_APC, .ALERTED, .TIMEOUT => {
            try alertable_syscall.checkCancel();
            continue;
        },
        else => |status| return alertable_syscall.unexpectedNtstatus(status),
    };

    var info: windows.PROCESS.BASIC_INFORMATION = undefined;
    const term: process.Child.Term = switch (windows.ntdll.NtQueryInformationProcess(
        handle,
        .BasicInformation,
        &info,
        @sizeOf(windows.PROCESS.BASIC_INFORMATION),
        null,
    )) {
        .SUCCESS => .{ .exited = @as(u8, @truncate(@backingInt(info.ExitStatus))) },
        else => .{ .unknown = 0 },
    };

    childCleanupWindows(child);
    return term;
}

pub fn childCleanupWindows(child: *process.Child) void {
    const handle = child.id orelse return;

    if (child.request_resource_usage_statistics) {
        var vmc: windows.PROCESS.VM_COUNTERS = undefined;
        switch (windows.ntdll.NtQueryInformationProcess(
            handle,
            .VmCounters,
            &vmc,
            @sizeOf(windows.PROCESS.VM_COUNTERS),
            null,
        )) {
            .SUCCESS => child.resource_usage_statistics.rusage = vmc,
            else => child.resource_usage_statistics.rusage = null,
        }
    }

    windows.CloseHandle(handle);
    child.id = null;

    windows.CloseHandle(child.thread_handle);
    child.thread_handle = undefined;

    if (child.stdin) |stdin| {
        windows.CloseHandle(stdin.handle);
        child.stdin = null;
    }
    if (child.stdout) |stdout| {
        windows.CloseHandle(stdout.handle);
        child.stdout = null;
    }
    if (child.stderr) |stderr| {
        windows.CloseHandle(stderr.handle);
        child.stderr = null;
    }
}

pub fn processSpawnWindows(userdata: ?*anyopaque, options: process.SpawnOptions) process.SpawnError!process.Child {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    var arena_allocator = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const cwd_w = cwd_w: {
        switch (options.cwd) {
            .inherit => break :cwd_w null,
            .dir => |cwd_dir| {
                var dir_path_buffer = try arena.alloc(u16, windows.PATH_MAX_WIDE + 1);
                const dir_path = try GetFinalPathNameByHandle(
                    cwd_dir.handle,
                    .{},
                    dir_path_buffer[0..windows.PATH_MAX_WIDE],
                );
                dir_path_buffer[dir_path.len] = 0;
                // Shrink the allocation down to just the path buffer + sentinel
                dir_path_buffer = try arena.realloc(dir_path_buffer, dir_path.len + 1);
                break :cwd_w dir_path_buffer[0..dir_path.len :0];
            },
            .path => |cwd| {
                break :cwd_w try std.unicode.wtf8ToWtf16LeAllocZ(arena, cwd);
            },
        }
    };
    const cwd_w_ptr = if (cwd_w) |cwd| cwd.ptr else null;

    // If the app name has more than just a filename, then we need to separate
    // that into the basename and dirname and use the dirname as an addition to
    // the cwd path. This is because NtQueryDirectoryFile cannot accept
    // FileName params with path separators.
    var app_w_buf: [windows.PATH_MAX_WIDE]u16 = undefined;
    // If the app name is absolute, then the cwd will already have the app's dirname in it,
    // so only populate app_dir if app name is a relative path with > 0 path separators.
    const app_path_w, const app_dir_w, const app_name_w = app: {
        const path = switch (options.exe) {
            .detect, .search, .path => options.argv[0],
            .file => |file| {
                const path_w = try GetFinalPathNameByHandle(file.handle, .{}, &app_w_buf);
                var path_it: Dir.path.ComponentIterator(.windows, u16) = .init(path_w);
                const base = path_it.last().?;
                break :app .{
                    null,
                    if (path_it.previous()) |dir| dir.path else path_it.root(),
                    base.name,
                };
            },
            .explicit => |explicit| explicit.path,
        };
        break :app .{
            if (Dir.path.isAbsolute(path)) null else switch (options.exe) {
                // The cwd provided by options is in effect when choosing the executable
                // path to match POSIX semantics.
                .detect, .search => cwd_w,
                .path => |dir| try GetFinalPathNameByHandle(dir.handle, .{}, &app_w_buf),
                .file => unreachable,
                .explicit => |explicit| try GetFinalPathNameByHandle(
                    explicit.dir.handle,
                    .{},
                    &app_w_buf,
                ),
            },
            if (Dir.path.dirname(path)) |app_dir|
                try std.unicode.wtf8ToWtf16LeAllocZ(arena, app_dir)
            else
                null,
            try std.unicode.wtf8ToWtf16LeAllocZ(arena, Dir.path.basename(path)),
        };
    };

    const flags: windows.CreateProcessFlags = .{
        .create_suspended = options.start_suspended,
        .create_unicode_environment = true,
        .create_no_window = options.create_no_window,
    };

    try mutexLock(&t.process_spawn_mutex);
    defer mutexUnlock(&t.process_spawn_mutex);

    const any_ignore =
        options.stdin == .ignore or
        options.stdout == .ignore or
        options.stderr == .ignore;
    const nul_handle = if (any_ignore) try getNulDevice(t) else undefined;

    const any_inherit =
        options.stdin == .inherit or
        options.stdout == .inherit or
        options.stderr == .inherit;
    const peb = if (any_inherit) windows.peb() else undefined;

    const stdin_pipe = if (options.stdin == .pipe) try windowsCreatePipe(t, .{
        .server = .{ .attributes = .{ .INHERIT = false }, .mode = .{ .IO = .SYNCHRONOUS_NONALERT } },
        .client = .{ .attributes = .{ .INHERIT = true }, .mode = .{ .IO = .SYNCHRONOUS_NONALERT } },
        .outbound = true,
    }) else undefined;
    errdefer if (options.stdin == .pipe) for (stdin_pipe) |handle| windows.CloseHandle(handle);

    const stdout_pipe = if (options.stdout == .pipe) try windowsCreatePipe(t, .{
        .server = .{ .attributes = .{ .INHERIT = false }, .mode = .{ .IO = .ASYNCHRONOUS } },
        .client = .{ .attributes = .{ .INHERIT = true }, .mode = .{ .IO = .SYNCHRONOUS_NONALERT } },
        .inbound = true,
    }) else undefined;
    errdefer if (options.stdout == .pipe) for (stdout_pipe) |handle| windows.CloseHandle(handle);

    const stderr_pipe = if (options.stderr == .pipe) try windowsCreatePipe(t, .{
        .server = .{ .attributes = .{ .INHERIT = false }, .mode = .{ .IO = .ASYNCHRONOUS } },
        .client = .{ .attributes = .{ .INHERIT = true }, .mode = .{ .IO = .SYNCHRONOUS_NONALERT } },
        .inbound = true,
    }) else undefined;
    errdefer if (options.stderr == .pipe) for (stderr_pipe) |handle| windows.CloseHandle(handle);

    const prog_pipe = if (options.progress_node.index != .none) try windowsCreatePipe(t, .{
        .server = .{ .attributes = .{ .INHERIT = false }, .mode = .{ .IO = .ASYNCHRONOUS } },
        .client = .{ .attributes = .{ .INHERIT = true }, .mode = .{ .IO = .ASYNCHRONOUS } },
        .inbound = true,
        .quota = std.Progress.max_packet_len * 2,
    }) else undefined;
    errdefer if (options.progress_node.index != .none) for (prog_pipe) |handle| windows.CloseHandle(handle);

    defer for (options.inherit_dirs) |inherit_dir| switch (windows.ntdll.NtSetInformationObject(
        inherit_dir.handle,
        .HandleFlag,
        &windows.OBJECT.HANDLE_FLAG{ .INHERIT = false },
        @sizeOf(windows.OBJECT.HANDLE_FLAG),
    )) {
        .SUCCESS => {},
        else => |status| windows.unexpectedStatus(status) catch {},
    };
    for (options.inherit_dirs) |inherit_dir| switch (windows.ntdll.NtSetInformationObject(
        inherit_dir.handle,
        .HandleFlag,
        &windows.OBJECT.HANDLE_FLAG{ .INHERIT = true },
        @sizeOf(windows.OBJECT.HANDLE_FLAG),
    )) {
        .SUCCESS => {},
        else => |status| return windows.unexpectedStatus(status),
    };
    defer for (options.inherit_files) |inherit_file| switch (windows.ntdll.NtSetInformationObject(
        inherit_file.handle,
        .HandleFlag,
        &windows.OBJECT.HANDLE_FLAG{ .INHERIT = false },
        @sizeOf(windows.OBJECT.HANDLE_FLAG),
    )) {
        .SUCCESS => {},
        else => |status| windows.unexpectedStatus(status) catch {},
    };
    for (options.inherit_files) |inherit_file| switch (windows.ntdll.NtSetInformationObject(
        inherit_file.handle,
        .HandleFlag,
        &windows.OBJECT.HANDLE_FLAG{ .INHERIT = true },
        @sizeOf(windows.OBJECT.HANDLE_FLAG),
    )) {
        .SUCCESS => {},
        else => |status| return windows.unexpectedStatus(status),
    };

    var siStartInfo: windows.STARTUPINFOW = .{
        .cb = @sizeOf(windows.STARTUPINFOW),
        .dwFlags = windows.STARTF_USESTDHANDLES,
        .hStdInput = switch (options.stdin) {
            .inherit => peb.ProcessParameters.hStdInput,
            .file => |file| try OpenFile(&.{}, .{
                .access_mask = .{
                    .STANDARD = .{ .SYNCHRONIZE = true },
                    .GENERIC = .{ .READ = true },
                },
                .dir = file.handle,
                .sa = &.{
                    .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
                    .lpSecurityDescriptor = null,
                    .bInheritHandle = .TRUE,
                },
                .creation = .OPEN,
            }),
            .ignore => nul_handle,
            .pipe => stdin_pipe[1],
            .close => null,
        },
        .hStdOutput = switch (options.stdout) {
            .inherit => peb.ProcessParameters.hStdOutput,
            .file => |file| try OpenFile(&.{}, .{
                .access_mask = .{
                    .STANDARD = .{ .SYNCHRONIZE = true },
                    .GENERIC = .{ .WRITE = true },
                },
                .dir = file.handle,
                .sa = &.{
                    .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
                    .lpSecurityDescriptor = null,
                    .bInheritHandle = .TRUE,
                },
                .creation = .OPEN,
            }),
            .ignore => nul_handle,
            .pipe => stdout_pipe[1],
            .close => null,
        },
        .hStdError = switch (options.stderr) {
            .inherit => peb.ProcessParameters.hStdError,
            .file => |file| try OpenFile(&.{}, .{
                .access_mask = .{
                    .STANDARD = .{ .SYNCHRONIZE = true },
                    .GENERIC = .{ .WRITE = true },
                },
                .dir = file.handle,
                .sa = &.{
                    .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
                    .lpSecurityDescriptor = null,
                    .bInheritHandle = .TRUE,
                },
                .creation = .OPEN,
            }),
            .ignore => nul_handle,
            .pipe => stderr_pipe[1],
            .close => null,
        },

        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .wShowWindow = 0,
        .cbReserved2 = 0,
        .lpReserved2 = null,
    };
    var piProcInfo: windows.PROCESS.INFORMATION = undefined;

    const env_block = env_block: {
        const prog_handle = if (options.progress_node.index != .none)
            prog_pipe[1]
        else
            windows.INVALID_HANDLE_VALUE;
        if (options.environ_map) |environ_map| break :env_block try environ_map.createWindowsBlock(arena, .{
            .zig_progress_handle = prog_handle,
        });
        break :env_block try t.environ.process_environ.createWindowsBlock(arena, .{
            .zig_progress_handle = if (options.progress_node.index != .none) prog_pipe[1] else windows.INVALID_HANDLE_VALUE,
        });
    };

    run: {
        // We have to scan each time because the PEB environment pointer is not stable.
        const env_strings: WindowsEnvironStrings = .scan();
        const PATH = env_strings.PATH orelse &[_:0]u16{};
        const PATHEXT = env_strings.PATHEXT orelse &[_:0]u16{};

        // In case the command ends up being a .bat/.cmd script, we need to escape things using the cmd.exe rules
        // and invoke cmd.exe ourselves in order to mitigate arbitrary command execution from maliciously
        // constructed arguments.
        //
        // We'll need to wait until we're actually trying to run the command to know for sure
        // if the resolved command has the `.bat` or `.cmd` extension, so we defer actually
        // serializing the command line until we determine how it should be serialized.
        var cmd_line_cache = WindowsCommandLineCache.init(arena, options.argv);

        var app_buf: std.ArrayList(u16) = .empty;
        try app_buf.appendSlice(arena, app_name_w);

        var dir_buf: std.ArrayList(u16) = .empty;

        if (app_path_w) |app_path| try dir_buf.appendSlice(arena, app_path);
        if (app_dir_w) |app_dir| {
            if (dir_buf.items.len > 0) try dir_buf.append(arena, Dir.path.sep);
            try dir_buf.appendSlice(arena, app_dir);
        }

        windowsCreateProcessPathExt(
            arena,
            &dir_buf,
            &app_buf,
            PATHEXT,
            &cmd_line_cache,
            env_block,
            cwd_w_ptr,
            flags,
            &siStartInfo,
            &piProcInfo,
        ) catch |no_path_err| {
            const original_err = switch (no_path_err) {
                // argv[0] contains unsupported characters that will never resolve to a valid exe.
                error.InvalidArg0 => return error.FileNotFound,
                error.FileNotFound, error.InvalidExe, error.AccessDenied => |e| e,
                error.UnrecoverableInvalidExe => return error.InvalidExe,
                else => |e| return e,
            };

            // We still search the path if the cwd is absolute because of the
            // "cwd provided by options is in effect when choosing the executable path
            // to match posix semantics" behavior--we don't want to skip searching
            // the PATH just because we were trying to set the cwd of the child process.
            if (switch (options.exe) {
                // If the app name had path separators, that disallows PATH searching.
                .detect => app_dir_w != null,
                // There's no need to search the PATH if the app name is absolute.
                .search => app_path_w == null,
                // PATH searching is disallowed.
                .path, .file, .explicit => true,
            }) return original_err;

            var it = std.mem.tokenizeScalar(u16, PATH, ';');
            while (it.next()) |search_path| {
                dir_buf.clearRetainingCapacity();
                try dir_buf.appendSlice(arena, search_path);

                if (windowsCreateProcessPathExt(
                    arena,
                    &dir_buf,
                    &app_buf,
                    PATHEXT,
                    &cmd_line_cache,
                    env_block,
                    cwd_w_ptr,
                    flags,
                    &siStartInfo,
                    &piProcInfo,
                )) {
                    break :run;
                } else |err| switch (err) {
                    // argv[0] contains unsupported characters that will never resolve to a valid exe.
                    error.InvalidArg0 => return error.FileNotFound,
                    error.FileNotFound, error.AccessDenied, error.InvalidExe => continue,
                    error.UnrecoverableInvalidExe => return error.InvalidExe,
                    else => |e| return e,
                }
            } else {
                return original_err;
            }
        };
    }

    if (options.progress_node.index != .none) {
        windows.CloseHandle(prog_pipe[1]);
        options.progress_node.setIpcFile(t, .{ .handle = prog_pipe[0], .flags = .{ .nonblocking = true } });
    }

    return .{
        .id = piProcInfo.hProcess,
        .thread_handle = piProcInfo.hThread,
        .stdin = stdin: switch (options.stdin) {
            .file => {
                windows.CloseHandle(siStartInfo.hStdInput.?);
                break :stdin null;
            },
            .pipe => {
                windows.CloseHandle(stdin_pipe[1]);
                break :stdin .{ .handle = stdin_pipe[0], .flags = .{ .nonblocking = false } };
            },
            else => null,
        },
        .stdout = stdout: switch (options.stdout) {
            .file => {
                windows.CloseHandle(siStartInfo.hStdOutput.?);
                break :stdout null;
            },
            .pipe => {
                windows.CloseHandle(stdout_pipe[1]);
                break :stdout .{ .handle = stdout_pipe[0], .flags = .{ .nonblocking = true } };
            },
            else => null,
        },
        .stderr = stderr: switch (options.stderr) {
            .file => {
                windows.CloseHandle(siStartInfo.hStdError.?);
                break :stderr null;
            },
            .pipe => {
                windows.CloseHandle(stderr_pipe[1]);
                break :stderr .{ .handle = stderr_pipe[0], .flags = .{ .nonblocking = true } };
            },
            else => null,
        },
        .request_resource_usage_statistics = options.request_resource_usage_statistics,
    };
}

pub fn getNulDevice(t: *Threaded) !windows.HANDLE {
    {
        try mutexLock(&t.mutex);
        defer mutexUnlock(&t.mutex);
        if (t.null_file.handle) |handle| return handle;
    }

    var fresh_handle: windows.HANDLE = undefined;
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtOpenFile(
        &fresh_handle,
        .{
            .STANDARD = .{ .SYNCHRONIZE = true },
            .SPECIFIC = .{ .FILE = .{ .READ_DATA = true, .WRITE_DATA = true } },
        },
        &.{
            .Attributes = .{ .INHERIT = true },
            .ObjectName = @constCast(&windows.UNICODE_STRING.init(
                &.{ '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 'u', 'l', 'l' },
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
            if (t.null_file.handle) |prev_handle| {
                windows.CloseHandle(fresh_handle);
                return prev_handle;
            } else {
                t.null_file.handle = fresh_handle;
                return fresh_handle;
            }
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

/// Expects `app_buf` to contain exactly the app name, and `dir_buf` to contain exactly the dir path.
/// After return, `app_buf` will always contain exactly the app name and `dir_buf` will always contain exactly the dir path.
/// Note: `app_buf` should not contain any leading path separators.
/// Note: If the dir is the cwd, dir_buf should be empty (len = 0).
pub fn windowsCreateProcessPathExt(
    arena: Allocator,
    dir_buf: *std.ArrayList(u16),
    app_buf: *std.ArrayList(u16),
    pathext: [:0]const u16,
    cmd_line_cache: *WindowsCommandLineCache,
    env_block: ?process.Environ.WindowsBlock,
    cwd_ptr: ?[*:0]u16,
    flags: windows.CreateProcessFlags,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS.INFORMATION,
) !void {
    const app_name_len = app_buf.items.len;
    const dir_path_len = dir_buf.items.len;

    if (app_name_len == 0) return error.FileNotFound;

    defer app_buf.shrinkRetainingCapacity(app_name_len);
    defer dir_buf.shrinkRetainingCapacity(dir_path_len);

    // The name of the game here is to avoid CreateProcessW calls at all costs,
    // and only ever try calling it when we have a real candidate for execution.
    // Secondarily, we want to minimize the number of syscalls used when checking
    // for each PATHEXT-appended version of the app name.
    //
    // An overview of the technique used:
    // - Open the search directory for iteration (either cwd or a path from PATH)
    // - Use NtQueryDirectoryFile with a wildcard filename of `<app name>*` to
    //   check if anything that could possibly match either the unappended version
    //   of the app name or any of the versions with a PATHEXT value appended exists.
    // - If the wildcard NtQueryDirectoryFile call found nothing, we can exit early
    //   without needing to use PATHEXT at all.
    //
    // This allows us to use a <open dir, NtQueryDirectoryFile, close dir> sequence
    // for any directory that doesn't contain any possible matches, instead of having
    // to use a separate look up for each individual filename combination (unappended +
    // each PATHEXT appended). For directories where the wildcard *does* match something,
    // we iterate the matches and take note of any that are either the unappended version,
    // or a version with a supported PATHEXT appended. We then try calling CreateProcessW
    // with the found versions in the appropriate order.
    const dir = dir: {
        // needs to be null-terminated
        try dir_buf.append(arena, 0);
        defer dir_buf.shrinkRetainingCapacity(dir_path_len);
        const dir_path_z = dir_buf.items[0 .. dir_buf.items.len - 1 :0];
        const prefixed_path = try wToPrefixedFileW(null, dir_path_z, .{});
        break :dir dirOpenDirWindows(.cwd(), prefixed_path.span(), .{
            .iterate = true,
        }) catch |err| switch (err) {
            // These errors must not be ignored because they should not be able
            // to affect which file is chosen to execute. Also `error.Canceled`
            // must never be swallowed.
            error.Canceled,
            error.SystemResources,
            error.Unexpected,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            => |e| return e,

            error.AccessDenied,
            error.PermissionDenied,
            error.SymLinkLoop,
            error.FileNotFound,
            error.NotDir,
            error.NoDevice,
            error.NetworkNotFound,
            error.NameTooLong,
            error.BadPathName,
            => return error.FileNotFound,
        };
    };
    defer windows.CloseHandle(dir.handle);

    // Add wildcard and null-terminator
    try app_buf.append(arena, '*');
    try app_buf.append(arena, 0);
    const app_name_wildcard = app_buf.items[0 .. app_buf.items.len - 1 :0];

    // This 2048 is arbitrary, we just want it to be large enough to get multiple FILE_DIRECTORY_INFORMATION entries
    // returned per NtQueryDirectoryFile call.
    var file_information_buf: [2048]u8 align(@alignOf(windows.FILE_DIRECTORY_INFORMATION)) = undefined;
    const file_info_maximum_single_entry_size = @sizeOf(windows.FILE_DIRECTORY_INFORMATION) + (windows.NAME_MAX * 2);
    if (file_information_buf.len < file_info_maximum_single_entry_size) {
        @compileError("file_information_buf must be large enough to contain at least one maximum size FILE_DIRECTORY_INFORMATION entry");
    }
    var io_status: windows.IO_STATUS_BLOCK = undefined;

    const num_supported_pathext = @typeInfo(process.WindowsExtension).@"enum".field_names.len;
    var pathext_seen: [num_supported_pathext]bool = @splat(false);
    var any_pathext_seen = false;
    var unappended_exists = false;

    // Fully iterate the wildcard matches via NtQueryDirectoryFile and take note of all versions
    // of the app_name we should try to spawn.
    // Note: This is necessary because the order of the files returned is filesystem-dependent:
    //       On NTFS, `blah.exe*` will always return `blah.exe` first if it exists.
    //       On FAT32, it's possible for something like `blah.exe.obj` to be returned first.
    while (true) {
        // If we get nothing with the wildcard, then we can just bail out
        // as we know appending PATHEXT will not yield anything.
        switch (windows.ntdll.NtQueryDirectoryFile(
            dir.handle,
            null,
            null,
            null,
            &io_status,
            &file_information_buf,
            file_information_buf.len,
            .Directory,
            .FALSE, // single result
            &.init(app_name_wildcard),
            .FALSE, // restart iteration
        )) {
            .SUCCESS => {},
            .NO_SUCH_FILE => return error.FileNotFound,
            .NO_MORE_FILES => break,
            .ACCESS_DENIED => return error.AccessDenied,
            else => |status| return windows.unexpectedStatus(status),
        }

        // According to the docs, this can only happen if there is not enough room in the
        // buffer to write at least one complete FILE_DIRECTORY_INFORMATION entry.
        // Therefore, this condition should not be possible to hit with the buffer size we use.
        std.debug.assert(io_status.Information != 0);

        var it = windows.FileInformationIterator(windows.FILE_DIRECTORY_INFORMATION){ .buf = &file_information_buf };
        while (it.next()) |info| {
            // Skip directories
            if (info.FileAttributes.DIRECTORY) continue;
            const filename = @as([*]u16, @ptrCast(&info.FileName))[0 .. info.FileNameLength / 2];
            // Because all results start with the app_name since we're using the wildcard `app_name*`,
            // if the length is equal to app_name then this is an exact match
            if (filename.len == app_name_len) {
                // Note: We can't break early here because it's possible that the unappended version
                //       fails to spawn, in which case we still want to try the PATHEXT appended versions.
                unappended_exists = true;
            } else if (windowsCreateProcessSupportsExtension(filename[app_name_len..])) |pathext_ext| {
                pathext_seen[@backingInt(pathext_ext)] = true;
                any_pathext_seen = true;
            }
        }
    }

    const unappended_err = unappended: {
        if (unappended_exists) {
            if (dir_path_len != 0) switch (dir_buf.items[dir_buf.items.len - 1]) {
                '/', '\\' => {},
                else => try dir_buf.append(arena, Dir.path.sep),
            };
            try dir_buf.appendSlice(arena, app_buf.items[0..app_name_len]);
            try dir_buf.append(arena, 0);
            const full_app_name = dir_buf.items[0 .. dir_buf.items.len - 1 :0];

            const is_bat_or_cmd = bat_or_cmd: {
                const app_name = app_buf.items[0..app_name_len];
                const ext_start = std.mem.findScalarLast(u16, app_name, '.') orelse break :bat_or_cmd false;
                const ext = app_name[ext_start..];
                const ext_enum = windowsCreateProcessSupportsExtension(ext) orelse break :bat_or_cmd false;
                switch (ext_enum) {
                    .cmd, .bat => break :bat_or_cmd true,
                    else => break :bat_or_cmd false,
                }
            };
            const cmd_line_w = if (is_bat_or_cmd)
                try cmd_line_cache.scriptCommandLine(full_app_name)
            else
                try cmd_line_cache.commandLine();
            const app_name_w = if (is_bat_or_cmd)
                try cmd_line_cache.cmdExePath()
            else
                full_app_name;

            if (windowsCreateProcess(
                app_name_w.ptr,
                cmd_line_w.ptr,
                env_block,
                cwd_ptr,
                flags,
                lpStartupInfo,
                lpProcessInformation,
            )) |_| {
                return;
            } else |err| switch (err) {
                error.FileNotFound,
                error.AccessDenied,
                => break :unappended err,
                error.InvalidExe => {
                    // On InvalidExe, if the extension of the app name is .exe then
                    // it's treated as an unrecoverable error. Otherwise, it'll be
                    // skipped as normal.
                    const app_name = app_buf.items[0..app_name_len];
                    const ext_start = std.mem.findScalarLast(u16, app_name, '.') orelse break :unappended err;
                    const ext = app_name[ext_start..];
                    if (windows.eqlIgnoreCaseWtf16(ext, std.unicode.utf8ToUtf16LeStringLiteral(".EXE"))) {
                        return error.UnrecoverableInvalidExe;
                    }
                    break :unappended err;
                },
                else => return err,
            }
        }
        break :unappended error.FileNotFound;
    };

    if (!any_pathext_seen) return unappended_err;

    // Now try any PATHEXT appended versions that we've seen
    var ext_it = std.mem.tokenizeScalar(u16, pathext, ';');
    while (ext_it.next()) |ext| {
        const ext_enum = windowsCreateProcessSupportsExtension(ext) orelse continue;
        if (!pathext_seen[@backingInt(ext_enum)]) continue;

        dir_buf.shrinkRetainingCapacity(dir_path_len);
        if (dir_path_len != 0) switch (dir_buf.items[dir_buf.items.len - 1]) {
            '/', '\\' => {},
            else => try dir_buf.append(arena, Dir.path.sep),
        };
        try dir_buf.appendSlice(arena, app_buf.items[0..app_name_len]);
        try dir_buf.appendSlice(arena, ext);
        try dir_buf.append(arena, 0);
        const full_app_name = dir_buf.items[0 .. dir_buf.items.len - 1 :0];

        const is_bat_or_cmd = switch (ext_enum) {
            .cmd, .bat => true,
            else => false,
        };
        const cmd_line_w = if (is_bat_or_cmd)
            try cmd_line_cache.scriptCommandLine(full_app_name)
        else
            try cmd_line_cache.commandLine();
        const app_name_w = if (is_bat_or_cmd)
            try cmd_line_cache.cmdExePath()
        else
            full_app_name;

        if (windowsCreateProcess(
            app_name_w.ptr,
            cmd_line_w.ptr,
            env_block,
            cwd_ptr,
            flags,
            lpStartupInfo,
            lpProcessInformation,
        )) |_| {
            return;
        } else |err| switch (err) {
            error.FileNotFound => continue,
            error.AccessDenied => continue,
            error.InvalidExe => {
                // On InvalidExe, if the extension of the app name is .exe then
                // it's treated as an unrecoverable error. Otherwise, it'll be
                // skipped as normal.
                if (windows.eqlIgnoreCaseWtf16(ext, std.unicode.utf8ToUtf16LeStringLiteral(".EXE"))) {
                    return error.UnrecoverableInvalidExe;
                }
                continue;
            },
            else => return err,
        }
    }

    return unappended_err;
}

pub fn windowsCreateProcess(
    app_name: [*:0]u16,
    cmd_line: [*:0]u16,
    env_block: ?process.Environ.WindowsBlock,
    cwd_ptr: ?[*:0]u16,
    flags: windows.CreateProcessFlags,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS.INFORMATION,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        if (windows.kernel32.CreateProcessW(
            app_name,
            cmd_line,
            null,
            null,
            .TRUE,
            flags,
            if (env_block) |block| block.slice.ptr else null,
            cwd_ptr,
            lpStartupInfo,
            lpProcessInformation,
        ).toBool()) {
            return syscall.finish();
        } else switch (windows.GetLastError()) {
            .INVALID_PARAMETER => unreachable,
            .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .FILE_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .DIRECTORY => return syscall.fail(error.FileNotFound),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .INVALID_NAME => return syscall.fail(error.InvalidName),
            .FILENAME_EXCED_RANGE => return syscall.fail(error.NameTooLong),
            .SHARING_VIOLATION => return syscall.fail(error.FileBusy),
            .COMMITMENT_LIMIT => return syscall.fail(error.SystemResources),

            // These are all the system errors that are mapped to ENOEXEC by
            // the undocumented _dosmaperr (old CRT) or __acrt_errno_map_os_error
            // (newer CRT) functions. Their code can be found in crt/src/dosmap.c (old SDK)
            // or urt/misc/errno.cpp (newer SDK) in the Windows SDK.
            .BAD_FORMAT,
            .INVALID_STARTING_CODESEG, // MIN_EXEC_ERROR in errno.cpp
            .INVALID_STACKSEG,
            .INVALID_MODULETYPE,
            .INVALID_EXE_SIGNATURE,
            .EXE_MARKED_INVALID,
            .BAD_EXE_FORMAT,
            .ITERATED_DATA_EXCEEDS_64k,
            .INVALID_MINALLOCSIZE,
            .DYNLINK_FROM_INVALID_RING,
            .IOPL_NOT_ENABLED,
            .INVALID_SEGDPL,
            .AUTODATASEG_EXCEEDS_64k,
            .RING2SEG_MUST_BE_MOVABLE,
            .RELOC_CHAIN_XEEDS_SEGLIM,
            .INFLOOP_IN_RELOC_CHAIN, // MAX_EXEC_ERROR in errno.cpp
            // This one is not mapped to ENOEXEC but it is possible, for example
            // when calling CreateProcessW on a plain text file with a .exe extension
            .EXE_MACHINE_TYPE_MISMATCH,
            => return syscall.fail(error.InvalidExe),

            else => |err| {
                syscall.finish();
                return windows.unexpectedError(err);
            },
        }
    }
}

/// Case-insensitive WTF-16 lookup
pub fn windowsCreateProcessSupportsExtension(ext: []const u16) ?process.WindowsExtension {
    comptime {
        // Ensures keeping this function in sync with the enum.
        const field_names = @typeInfo(process.WindowsExtension).@"enum".field_names;
        assert(field_names.len == 4);
        assert(@backingInt(process.WindowsExtension.bat) == 0);
        assert(@backingInt(process.WindowsExtension.cmd) == 1);
        assert(@backingInt(process.WindowsExtension.com) == 2);
        assert(@backingInt(process.WindowsExtension.exe) == 3);
    }

    if (ext.len != 4) return null;
    const State = enum {
        start,
        dot,
        b,
        ba,
        c,
        cm,
        co,
        e,
        ex,
    };
    var state: State = .start;
    for (ext) |c| switch (state) {
        .start => switch (c) {
            '.' => state = .dot,
            else => return null,
        },
        .dot => switch (c) {
            'b', 'B' => state = .b,
            'c', 'C' => state = .c,
            'e', 'E' => state = .e,
            else => return null,
        },
        .b => switch (c) {
            'a', 'A' => state = .ba,
            else => return null,
        },
        .c => switch (c) {
            'm', 'M' => state = .cm,
            'o', 'O' => state = .co,
            else => return null,
        },
        .e => switch (c) {
            'x', 'X' => state = .ex,
            else => return null,
        },
        .ba => switch (c) {
            't', 'T' => return .bat,
            else => return null,
        },
        .cm => switch (c) {
            'd', 'D' => return .cmd,
            else => return null,
        },
        .co => switch (c) {
            'm', 'M' => return .com,
            else => return null,
        },
        .ex => switch (c) {
            'e', 'E' => return .exe,
            else => return null,
        },
    };
    return null;
}

test windowsCreateProcessSupportsExtension {
    try std.testing.expectEqual(process.WindowsExtension.exe, windowsCreateProcessSupportsExtension(&[_]u16{ '.', 'e', 'X', 'e' }).?);
    try std.testing.expect(windowsCreateProcessSupportsExtension(&[_]u16{ '.', 'e', 'X', 'e', 'c' }) == null);
}

/// Serializes argv into a WTF-16 encoded command-line string for use with CreateProcessW.
///
/// Serialization is done on-demand and the result is cached in order to allow for:
/// - Only serializing the particular type of command line needed (`.bat`/`.cmd`
///   command line serialization is different from `.exe`/etc)
/// - Reusing the serialized command lines if necessary (i.e. if the execution
///   of a command fails and the PATH is going to be continued to be searched
///   for more candidates)
pub const WindowsCommandLineCache = struct {
    cmd_line: ?[:0]u16 = null,
    script_cmd_line: ?[:0]u16 = null,
    cmd_exe_path: ?[:0]u16 = null,
    argv: []const []const u8,
    allocator: Allocator,

    fn init(allocator: Allocator, argv: []const []const u8) WindowsCommandLineCache {
        return .{
            .allocator = allocator,
            .argv = argv,
        };
    }

    fn deinit(self: *WindowsCommandLineCache) void {
        if (self.cmd_line) |cmd_line| self.allocator.free(cmd_line);
        if (self.script_cmd_line) |script_cmd_line| self.allocator.free(script_cmd_line);
        if (self.cmd_exe_path) |cmd_exe_path| self.allocator.free(cmd_exe_path);
    }

    fn commandLine(self: *WindowsCommandLineCache) ![:0]u16 {
        if (self.cmd_line == null) {
            self.cmd_line = try argvToCommandLineWindows(self.allocator, self.argv);
        }
        return self.cmd_line.?;
    }

    /// Not cached, since the path to the batch script will change during PATH searching.
    /// `script_path` should be as qualified as possible, e.g. if the PATH is being searched,
    /// then script_path should include both the search path and the script filename
    /// (this allows avoiding cmd.exe having to search the PATH again).
    fn scriptCommandLine(self: *WindowsCommandLineCache, script_path: []const u16) ![:0]u16 {
        if (self.script_cmd_line) |v| self.allocator.free(v);
        self.script_cmd_line = try argvToScriptCommandLineWindows(
            self.allocator,
            script_path,
            self.argv[1..],
        );
        return self.script_cmd_line.?;
    }

    fn cmdExePath(self: *WindowsCommandLineCache) Allocator.Error![:0]u16 {
        if (self.cmd_exe_path == null) {
            // Remove trailing slash from system directory path; we'll re-add it below
            const system_dir = std.mem.trimEnd(u16, windows.getSystemDirectoryWtf16Le(), &.{ '/', '\\' });
            const suffix = std.unicode.utf8ToUtf16LeStringLiteral("\\cmd.exe");
            const buf = try self.allocator.allocSentinel(u16, system_dir.len + suffix.len, 0);
            errdefer comptime unreachable;
            @memcpy(buf[0..system_dir.len], system_dir);
            @memcpy(buf[system_dir.len..], suffix);
            self.cmd_exe_path = buf;
        }
        return self.cmd_exe_path.?;
    }
};

pub const ArgvToScriptCommandLineError = error{
    OutOfMemory,
    InvalidWtf8,
    /// NUL (U+0000), LF (U+000A), CR (U+000D) are not allowed
    /// within arguments when executing a `.bat`/`.cmd` script.
    /// - NUL/LF signifiies end of arguments, so anything afterwards
    ///   would be lost after execution.
    /// - CR is stripped by `cmd.exe`, so any CR codepoints
    ///   would be lost after execution.
    InvalidBatchScriptArg,
};

/// Serializes `argv` to a Windows command-line string that uses `cmd.exe /c` and `cmd.exe`-specific
/// escaping rules. The caller owns the returned slice.
///
/// Escapes `argv` using the suggested mitigation against arbitrary command execution from:
/// https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/
///
/// The return of this function will look like
/// `cmd.exe /d /e:ON /v:OFF /c "<escaped command line>"`
/// and should be used as the `lpCommandLine` of `CreateProcessW`, while the return of
/// `WindowsCommandLineCache.cmdExePath` should be used as `lpApplicationName`.
///
/// Should only be used when spawning `.bat`/`.cmd` scripts, see `argvToCommandLineWindows` otherwise.
/// The `.bat`/`.cmd` file must be known to both have the `.bat`/`.cmd` extension and exist on the filesystem.
pub fn argvToScriptCommandLineWindows(
    allocator: Allocator,
    /// Path to the `.bat`/`.cmd` script. If this path is relative, it is assumed to be relative to the CWD.
    /// The script must have been verified to exist at this path before calling this function.
    script_path: []const u16,
    /// Arguments, not including the script name itself. Expected to be encoded as WTF-8.
    script_args: []const []const u8,
) ArgvToScriptCommandLineError![:0]u16 {
    var buf = try std.array_list.Managed(u8).initCapacity(allocator, 64);
    defer buf.deinit();

    // `/d` disables execution of AutoRun commands.
    // `/e:ON` and `/v:OFF` are needed for BatBadBut mitigation:
    // > If delayed expansion is enabled via the registry value DelayedExpansion,
    // > it must be disabled by explicitly calling cmd.exe with the /V:OFF option.
    // > Escaping for % requires the command extension to be enabled.
    // > If it’s disabled via the registry value EnableExtensions, it must be enabled with the /E:ON option.
    // https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/
    buf.appendSliceAssumeCapacity("cmd.exe /d /e:ON /v:OFF /c \"");

    // Always quote the path to the script arg
    buf.appendAssumeCapacity('"');
    // We always want the path to the batch script to include a path separator in order to
    // avoid cmd.exe searching the PATH for the script. This is not part of the arbitrary
    // command execution mitigation, we just know exactly what script we want to execute
    // at this point, and potentially making cmd.exe re-find it is unnecessary.
    //
    // If the script path does not have a path separator, then we know its relative to CWD and
    // we can just put `.\` in the front.
    if (std.mem.findAny(u16, script_path, &[_]u16{
        std.mem.nativeToLittle(u16, '\\'), std.mem.nativeToLittle(u16, '/'),
    }) == null) {
        try buf.appendSlice(".\\");
    }
    // Note that we don't do any escaping/mitigations for this argument, since the relevant
    // characters (", %, etc) are illegal in file paths and this function should only be called
    // with script paths that have been verified to exist.
    try std.unicode.wtf16LeToWtf8ArrayList(&buf, script_path);
    buf.appendAssumeCapacity('"');

    for (script_args) |arg| {
        // Literal carriage returns get stripped when run through cmd.exe
        // and NUL/newlines act as 'end of command.' Because of this, it's basically
        // always a mistake to include these characters in argv, so it's
        // an error condition in order to ensure that the return of this
        // function can always roundtrip through cmd.exe.
        if (std.mem.findAny(u8, arg, "\x00\r\n") != null) {
            return error.InvalidBatchScriptArg;
        }

        // Separate args with a space.
        try buf.append(' ');

        // Need to quote if the argument is empty (otherwise the arg would just be lost)
        // or if the last character is a `\`, since then something like "%~2" in a .bat
        // script would cause the closing " to be escaped which we don't want.
        var needs_quotes = arg.len == 0 or arg[arg.len - 1] == '\\';
        if (!needs_quotes) {
            for (arg) |c| {
                switch (c) {
                    // Known good characters that don't need to be quoted
                    'A'...'Z', 'a'...'z', '0'...'9', '#', '$', '*', '+', '-', '.', '/', ':', '?', '@', '\\', '_' => {},
                    // When in doubt, quote
                    else => {
                        needs_quotes = true;
                        break;
                    },
                }
            }
        }
        if (needs_quotes) {
            try buf.append('"');
        }
        var backslashes: usize = 0;
        for (arg) |c| {
            switch (c) {
                '\\' => {
                    backslashes += 1;
                },
                '"' => {
                    try buf.appendNTimes('\\', backslashes);
                    try buf.append('"');
                    backslashes = 0;
                },
                // Replace `%` with `%%cd:~,%`.
                //
                // cmd.exe allows extracting a substring from an environment
                // variable with the syntax: `%foo:~<start_index>,<end_index>%`.
                // Therefore, `%cd:~,%` will always expand to an empty string
                // since both the start and end index are blank, and it is assumed
                // that `%cd%` is always available since it is a built-in variable
                // that corresponds to the current directory.
                //
                // This means that replacing `%foo%` with `%%cd:~,%foo%%cd:~,%`
                // will stop `%foo%` from being expanded and *after* expansion
                // we'll still be left with `%foo%` (the literal string).
                '%' => {
                    // the trailing `%` is appended outside the switch
                    try buf.appendSlice("%%cd:~,");
                    backslashes = 0;
                },
                else => {
                    backslashes = 0;
                },
            }
            try buf.append(c);
        }
        if (needs_quotes) {
            try buf.appendNTimes('\\', backslashes);
            try buf.append('"');
        }
    }

    try buf.append('"');

    return try std.unicode.wtf8ToWtf16LeAllocZ(allocator, buf.items);
}

/// Serializes `argv` to a Windows command-line string suitable for passing to a child process and
/// parsing by the `CommandLineToArgvW` algorithm. The caller owns the returned slice.
///
/// To avoid arbitrary command execution, this function should not be used when spawning `.bat`/`.cmd` scripts.
/// https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/
///
/// When executing `.bat`/`.cmd` scripts, use `argvToScriptCommandLineWindows` instead.
pub fn argvToCommandLineWindows(
    allocator: Allocator,
    argv: []const []const u8,
) ArgvToCommandLineError![:0]u16 {
    var buf = std.array_list.Managed(u8).init(allocator);
    defer buf.deinit();

    if (argv.len != 0) {
        const arg0 = argv[0];

        // The first argument must be quoted if it contains spaces or ASCII control characters
        // (excluding DEL). It also follows special quoting rules where backslashes have no special
        // interpretation, which makes it impossible to pass certain first arguments containing
        // double quotes to a child process without characters from the first argument leaking into
        // subsequent ones (which could have security implications).
        //
        // Empty arguments technically don't need quotes, but we quote them anyway for maximum
        // compatibility with different implementations of the 'CommandLineToArgvW' algorithm.
        //
        // Double quotes are illegal in paths on Windows, so for the sake of simplicity we reject
        // all first arguments containing double quotes, even ones that we could theoretically
        // serialize in unquoted form.
        var needs_quotes = arg0.len == 0;
        for (arg0) |c| {
            if (c <= ' ') {
                needs_quotes = true;
            } else if (c == '"') {
                return error.InvalidArg0;
            }
        }
        if (needs_quotes) {
            try buf.append('"');
            try buf.appendSlice(arg0);
            try buf.append('"');
        } else {
            try buf.appendSlice(arg0);
        }

        for (argv[1..]) |arg| {
            try buf.append(' ');

            // Subsequent arguments must be quoted if they contain spaces, tabs or double quotes,
            // or if they are empty. For simplicity and for maximum compatibility with different
            // implementations of the 'CommandLineToArgvW' algorithm, we also quote all ASCII
            // control characters (again, excluding DEL).
            needs_quotes = for (arg) |c| {
                if (c <= ' ' or c == '"') {
                    break true;
                }
            } else arg.len == 0;
            if (!needs_quotes) {
                try buf.appendSlice(arg);
                continue;
            }

            try buf.append('"');
            var backslash_count: usize = 0;
            for (arg) |byte| {
                switch (byte) {
                    '\\' => {
                        backslash_count += 1;
                    },
                    '"' => {
                        try buf.appendNTimes('\\', backslash_count * 2 + 1);
                        try buf.append('"');
                        backslash_count = 0;
                    },
                    else => {
                        try buf.appendNTimes('\\', backslash_count);
                        try buf.append(byte);
                        backslash_count = 0;
                    },
                }
            }
            try buf.appendNTimes('\\', backslash_count * 2);
            try buf.append('"');
        }
    }

    return try std.unicode.wtf8ToWtf16LeAllocZ(allocator, buf.items);
}

test argvToCommandLineWindows {
    const t = testArgvToCommandLineWindows;

    try t(&.{
        \\C:\Program Files\zig\zig.exe
        ,
        \\run
        ,
        \\.\src\main.zig
        ,
        \\-target
        ,
        \\x86_64-windows-gnu
        ,
        \\-O
        ,
        \\safe
        ,
        \\--
        ,
        \\--emoji=🗿
        ,
        \\--eval=new Regex("Dwayne \"The Rock\" Johnson")
        ,
    },
        \\"C:\Program Files\zig\zig.exe" run .\src\main.zig -target x86_64-windows-gnu -O safe -- --emoji=🗿 "--eval=new Regex(\"Dwayne \\\"The Rock\\\" Johnson\")"
    );

    try t(&.{}, "");
    try t(&.{""}, "\"\"");
    try t(&.{" "}, "\" \"");
    try t(&.{"\t"}, "\"\t\"");
    try t(&.{"\x07"}, "\"\x07\"");
    try t(&.{"🦎"}, "🦎");

    try t(
        &.{ "zig", "aa aa", "bb\tbb", "cc\ncc", "dd\r\ndd", "ee\x7Fee" },
        "zig \"aa aa\" \"bb\tbb\" \"cc\ncc\" \"dd\r\ndd\" ee\x7Fee",
    );

    try t(
        &.{ "\\\\foo bar\\foo bar\\", "\\\\zig zag\\zig zag\\" },
        "\"\\\\foo bar\\foo bar\\\" \"\\\\zig zag\\zig zag\\\\\"",
    );

    try std.testing.expectError(
        error.InvalidArg0,
        argvToCommandLineWindows(std.testing.allocator, &.{"\"quotes\"quotes\""}),
    );
    try std.testing.expectError(
        error.InvalidArg0,
        argvToCommandLineWindows(std.testing.allocator, &.{"quotes\"quotes"}),
    );
    try std.testing.expectError(
        error.InvalidArg0,
        argvToCommandLineWindows(std.testing.allocator, &.{"q u o t e s \" q u o t e s"}),
    );
}

pub fn testArgvToCommandLineWindows(argv: []const []const u8, expected_cmd_line: []const u8) !void {
    const cmd_line_w = try argvToCommandLineWindows(std.testing.allocator, argv);
    defer std.testing.allocator.free(cmd_line_w);

    const cmd_line = try std.unicode.wtf16LeToWtf8Alloc(std.testing.allocator, cmd_line_w);
    defer std.testing.allocator.free(cmd_line);

    try std.testing.expectEqualStrings(expected_cmd_line, cmd_line);
}

pub const CreatePipeOptions = struct {
    server: End,
    client: End,
    inbound: bool = false,
    outbound: bool = false,
    maximum_instances: u32 = 1,
    quota: u32 = 4096,
    default_timeout: windows.LARGE_INTEGER = -120 * std.time.ns_per_s / 100,

    pub const End = struct {
        attributes: windows.OBJECT.ATTRIBUTES.Flags = .{},
        mode: windows.FILE.MODE,
    };
};
pub fn windowsCreatePipe(t: *Threaded, options: CreatePipeOptions) ![2]windows.HANDLE {
    const named_pipe_device = try t.getNamedPipeDevice();
    const server_handle = server_handle: {
        var handle: windows.HANDLE = undefined;
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtCreateNamedPipeFile(
            &handle,
            .{
                .SPECIFIC = .{ .FILE_PIPE = .{
                    .READ_DATA = options.inbound,
                    .WRITE_DATA = options.outbound,
                    .WRITE_ATTRIBUTES = true,
                    .READ_ATTRIBUTES = true,
                } },
                .STANDARD = .{ .SYNCHRONIZE = true },
            },
            &.{
                .RootDirectory = named_pipe_device,
                .Attributes = options.server.attributes,
            },
            &io_status_block,
            .{ .READ = true, .WRITE = true },
            .CREATE,
            options.server.mode,
            .{ .TYPE = .BYTE_STREAM },
            .{ .MODE = .BYTE_STREAM },
            .{ .OPERATION = .QUEUE },
            options.maximum_instances,
            if (options.inbound) options.quota else 0,
            if (options.outbound) options.quota else 0,
            &options.default_timeout,
        )) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INVALID_PARAMETER => |status| return syscall.ntstatusBug(status),
            .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
        break :server_handle handle;
    };
    errdefer windows.CloseHandle(server_handle);
    const client_handle = client_handle: {
        var handle: windows.HANDLE = undefined;
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtOpenFile(
            &handle,
            .{
                .SPECIFIC = .{ .FILE_PIPE = .{
                    .READ_DATA = options.outbound,
                    .WRITE_DATA = options.inbound,
                    .WRITE_ATTRIBUTES = true,
                    .READ_ATTRIBUTES = true,
                } },
                .STANDARD = .{ .SYNCHRONIZE = true },
            },
            &.{
                .RootDirectory = server_handle,
                .Attributes = options.client.attributes,
            },
            &io_status_block,
            .{ .READ = true, .WRITE = true },
            options.client.mode,
        )) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INVALID_PARAMETER => |status| return syscall.ntstatusBug(status),
            .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
        break :client_handle handle;
    };
    errdefer windows.CloseHandle(client_handle);
    return .{ server_handle, client_handle };
}

pub fn fallbackSeedWindows(seed: *[Csprng.seed_len]u8) void {
    var pc: windows.LARGE_INTEGER = undefined;
    _ = windows.ntdll.RtlQueryPerformanceCounter(&pc);
    std.mem.writeInt(windows.LARGE_INTEGER, seed[0..@sizeOf(windows.LARGE_INTEGER)], pc, .native);
}

pub fn timeoutToWindowsInterval(timeout: Io.Timeout) ?windows.LARGE_INTEGER {
    // ntdll only supports two combinations:
    // * real-time (`.real`) sleeps with absolute deadlines
    // * monotonic (`.awake`/`.boot`) sleeps with relative durations
    const clock = switch (timeout) {
        .none => return null,
        .duration => |d| d.clock,
        .deadline => |d| d.clock,
    };
    switch (clock) {
        .cpu_process, .cpu_thread => unreachable, // cannot sleep for CPU time
        .real => {
            const deadline = switch (timeout) {
                .none => unreachable,
                .duration => |d| nowWindows(clock).addDuration(d.raw),
                .deadline => |d| d.raw,
            };
            const epoch_ns = std.time.epoch.windows * std.time.ns_per_s;
            return @intCast(@max(@divTrunc(deadline.nanoseconds - epoch_ns, 100), 0));
        },
        .awake, .boot => {
            const duration = switch (timeout) {
                .none => unreachable,
                .duration => |d| d.raw,
                .deadline => |d| nowWindows(clock).durationTo(d.raw),
            };
            return @intCast(@min(@divTrunc(-duration.nanoseconds, 100), -1));
        },
    }
}
