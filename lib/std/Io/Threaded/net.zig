//! The net part of `std.Io.Threaded`, in its own file so that a compiler
//! building for another system never loads it.

const Threaded = @import("../Threaded.zig");
const windows_impl = Threaded.windows_impl;
const AlertableSyscall = Threaded.AlertableSyscall;
const File = Threaded.File;
const HostName = Threaded.HostName;
const Io = Threaded.Io;
const IpAddress = Threaded.IpAddress;
const PosixAddress = Threaded.PosixAddress;
const Syscall = Threaded.Syscall;
const Thread = Threaded.Thread;
const UnixAddress = Threaded.UnixAddress;
const addBuf = Threaded.addBuf;
const addressFromPosix = Threaded.addressFromPosix;
const addressToPosix = Threaded.addressToPosix;
const addressUnixToPosix = Threaded.addressUnixToPosix;
const assert = Threaded.assert;
const builtin = Threaded.builtin;
const closeFd = Threaded.closeFd;
const dirOpenFile = Threaded.dirOpenFile;
const errnoBug = Threaded.errnoBug;
const fileClose = Threaded.fileClose;
const have_accept4 = Threaded.have_accept4;
const have_networking = Threaded.have_networking;
const have_sendmmsg = Threaded.have_sendmmsg;
const io = Threaded.io;
const is_darwin = Threaded.is_darwin;
const is_windows = Threaded.is_windows;
const max_iovecs_len = Threaded.max_iovecs_len;
const native_os = Threaded.native_os;
const net = Threaded.net;
const posix = Threaded.posix;
const posixAddressFamily = Threaded.posixAddressFamily;
const posixSocketModeProtocol = Threaded.posixSocketModeProtocol;
const random = Threaded.random;
const setCloexec = Threaded.setCloexec;
const socket_flags_unsupported = Threaded.socket_flags_unsupported;
const splat_buffer_size = Threaded.splat_buffer_size;
const std = Threaded.std;
const waitForApcOrAlert = Threaded.waitForApcOrAlert;
const windows = Threaded.windows;

pub fn netWriteFile(
    userdata: ?*anyopaque,
    socket_handle: net.Socket.Handle,
    header: []const u8,
    file_reader: *File.Reader,
    limit: Io.Limit,
) net.Stream.Writer.WriteFileError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = socket_handle;
    _ = header;
    _ = file_reader;
    _ = limit;
    // TODO implement netWriteFile
    return error.Unimplemented;
}

pub fn netListenIpPosix(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.ListenOptions,
) IpAddress.ListenError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_fd = try openSocketPosix(family, .{ .mode = options.mode, .protocol = options.protocol });
    errdefer closeFd(socket_fd);

    if (options.reuse_address) {
        try setSocketOptionPosix(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);
        if (@hasDecl(posix.SO, "REUSEPORT"))
            try setSocketOptionPosix(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, 1);
    }

    var storage: PosixAddress = undefined;
    var addr_len = addressToPosix(address, &storage);
    try posixBind(socket_fd, &storage.any, addr_len);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.listen(socket_fd, options.kernel_backlog))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ADDRINUSE => return syscall.fail(error.AddressInUse),
            .BADF => |err| return syscall.errnoBug(err), // File descriptor used after closed.
            else => |err| return syscall.unexpectedErrno(err),
        }
    }

    try posixGetSockName(socket_fd, &storage.any, &addr_len);
    return .{ .handle = socket_fd, .address = addressFromPosix(&storage) };
}

pub fn netListenUnixPosix(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
    options: net.UnixAddress.ListenOptions,
) net.UnixAddress.ListenError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const socket_fd = openSocketPosix(posix.AF.UNIX, .{ .mode = .stream }) catch |err| switch (err) {
        error.ProtocolUnsupportedBySystem => return error.AddressFamilyUnsupported,
        error.ProtocolUnsupportedByAddressFamily => return error.AddressFamilyUnsupported,
        error.SocketModeUnsupported => return error.AddressFamilyUnsupported,
        error.OptionUnsupported => return error.Unexpected,
        else => |e| return e,
    };
    errdefer closeFd(socket_fd);

    var storage: UnixAddress = undefined;
    const addr_len = addressUnixToPosix(address, &storage);
    try posixBindUnix(socket_fd, &storage.any, addr_len);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.listen(socket_fd, options.kernel_backlog))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ADDRINUSE => return syscall.fail(error.AddressInUse),
            .BADF => |err| return syscall.errnoBug(err), // File descriptor used after closed.
            else => |err| return syscall.unexpectedErrno(err),
        }
    }

    return socket_fd;
}

pub fn posixBindUnix(
    fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.bind(fd, addr, addr_len))) {
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
                    .ADDRINUSE => return error.AddressInUse,
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .ADDRNOTAVAIL => return error.AddressUnavailable,
                    .NOMEM => return error.SystemResources,

                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .PERM => return error.PermissionDenied,

                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOTSOCK => |err| return errnoBug(err), // invalid `sockfd`
                    .FAULT => |err| return errnoBug(err), // invalid `addr` pointer
                    .NAMETOOLONG => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn posixBind(
    socket_fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.bind(socket_fd, addr, addr_len))) {
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
                    .ADDRINUSE => return error.AddressInUse,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOTSOCK => |err| return errnoBug(err), // invalid `sockfd`
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .ADDRNOTAVAIL => return error.AddressUnavailable,
                    .FAULT => |err| return errnoBug(err), // invalid `addr` pointer
                    .NOMEM => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn posixConnect(
    socket_fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.connect(socket_fd, addr, addr_len))) {
        .SUCCESS => {
            syscall.finish();
            return;
        },
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .ADDRNOTAVAIL => return syscall.fail(error.AddressUnavailable),
        .AFNOSUPPORT => return syscall.fail(error.AddressFamilyUnsupported),
        .AGAIN, .INPROGRESS => return syscall.fail(error.WouldBlock),
        .ALREADY => return syscall.fail(error.ConnectionPending),
        .CONNREFUSED => return syscall.fail(error.ConnectionRefused),
        .CONNRESET => return syscall.fail(error.ConnectionResetByPeer),
        .HOSTUNREACH => return syscall.fail(error.HostUnreachable),
        .NETUNREACH => return syscall.fail(error.NetworkUnreachable),
        .TIMEDOUT => return syscall.fail(error.Timeout),
        .ACCES => return syscall.fail(error.AccessDenied),
        .NETDOWN => return syscall.fail(error.NetworkDown),
        .BADF => |err| return syscall.errnoBug(err), // File descriptor used after closed.
        .CONNABORTED => |err| return syscall.errnoBug(err),
        .FAULT => |err| return syscall.errnoBug(err),
        .ISCONN => |err| return syscall.errnoBug(err),
        .NOENT => |err| return syscall.errnoBug(err),
        .NOTSOCK => |err| return syscall.errnoBug(err),
        .PERM => |err| return syscall.errnoBug(err),
        .PROTOTYPE => |err| return syscall.errnoBug(err),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

pub fn posixConnectUnix(
    fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.connect(fd, addr, addr_len))) {
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
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .AGAIN => return error.WouldBlock,
                    .INPROGRESS => return error.WouldBlock,
                    .ACCES => return error.AccessDenied,

                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .PERM => return error.PermissionDenied,
                    .CONNREFUSED => return error.ConnectionRefused,

                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNABORTED => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .ISCONN => |err| return errnoBug(err),
                    .NOTSOCK => |err| return errnoBug(err),
                    .PROTOTYPE => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn posixGetSockName(
    socket_fd: posix.fd_t,
    addr: *posix.sockaddr,
    addr_len: *posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.getsockname(socket_fd, addr, addr_len))) {
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
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOTSOCK => |err| return errnoBug(err), // always a race condition
                    .NOBUFS => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn setSocketOptionPosix(fd: posix.fd_t, level: i32, opt_name: u32, option: u32) !void {
    const o: []const u8 = @ptrCast(&option);
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.setsockopt(fd, level, opt_name, o.ptr, @intCast(o.len)))) {
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
                    .NOTSOCK => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn netConnectIpPosix(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.ConnectOptions,
) IpAddress.ConnectError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    if (options.timeout != .none) @panic("TODO implement netConnectIpPosix with timeout");
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_fd = try openSocketPosix(family, .{ .mode = options.mode, .protocol = options.protocol });
    errdefer closeFd(socket_fd);
    var storage: PosixAddress = undefined;
    var addr_len = addressToPosix(address, &storage);
    try posixConnect(socket_fd, &storage.any, addr_len);
    try posixGetSockName(socket_fd, &storage.any, &addr_len);
    return .{ .handle = socket_fd, .address = addressFromPosix(&storage) };
}

pub fn netConnectUnixPosix(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
) net.UnixAddress.ConnectError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const socket_fd = openSocketPosix(posix.AF.UNIX, .{ .mode = .stream }) catch |err| switch (err) {
        error.ProtocolUnsupportedByAddressFamily => return error.AddressFamilyUnsupported,
        error.OptionUnsupported => return error.Unexpected,
        else => |e| return e,
    };
    errdefer closeFd(socket_fd);
    var storage: UnixAddress = undefined;
    const addr_len = addressUnixToPosix(address, &storage);
    try posixConnectUnix(socket_fd, &storage.any, addr_len);
    return socket_fd;
}

pub fn netBindIpPosix(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.BindOptions,
) IpAddress.BindError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_fd = try openSocketPosix(family, options);
    errdefer closeFd(socket_fd);
    var storage: PosixAddress = undefined;
    var addr_len = addressToPosix(address, &storage);
    try posixBind(socket_fd, &storage.any, addr_len);
    if (options.allow_broadcast) try setSocketOptionPosix(socket_fd, std.posix.SOL.SOCKET, std.posix.SO.BROADCAST, 1);
    try posixGetSockName(socket_fd, &storage.any, &addr_len);
    return .{ .handle = socket_fd, .address = addressFromPosix(&storage) };
}

pub fn openSocketPosix(
    family: posix.sa_family_t,
    options: IpAddress.BindOptions,
) error{
    AddressFamilyUnsupported,
    ProtocolUnsupportedBySystem,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    ProtocolUnsupportedByAddressFamily,
    SocketModeUnsupported,
    OptionUnsupported,
    Unexpected,
    Canceled,
}!posix.socket_t {
    const mode, const protocol = try posixSocketModeProtocol(family, options.mode, options.protocol);
    const flags: u32 = mode | if (socket_flags_unsupported) 0 else posix.SOCK.CLOEXEC;
    const syscall: Syscall = try .start();
    const socket_fd = while (true) {
        const rc = posix.system.socket(family, flags, protocol);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const fd: posix.fd_t = @intCast(rc);
                errdefer closeFd(fd);
                if (socket_flags_unsupported) try setCloexec(fd);
                break fd;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .AFNOSUPPORT => return syscall.fail(error.AddressFamilyUnsupported),
            .INVAL => return syscall.fail(error.ProtocolUnsupportedBySystem),
            .MFILE => return syscall.fail(error.ProcessFdQuotaExceeded),
            .NFILE => return syscall.fail(error.SystemFdQuotaExceeded),
            .NOBUFS => return syscall.fail(error.SystemResources),
            .NOMEM => return syscall.fail(error.SystemResources),
            .PROTONOSUPPORT => return syscall.fail(error.ProtocolUnsupportedByAddressFamily),
            .PROTOTYPE => return syscall.fail(error.SocketModeUnsupported),
            else => |err| return syscall.unexpectedErrno(err),
        }
    };
    errdefer closeFd(socket_fd);

    if (options.ip6_only) |ip6_only| {
        if (posix.IPV6 == void) return error.OptionUnsupported;
        try setSocketOptionPosix(socket_fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, @intFromBool(ip6_only));
    }

    return socket_fd;
}

pub fn netSocketCreatePair(
    userdata: ?*anyopaque,
    options: net.Socket.CreatePairOptions,
) net.Socket.CreatePairError![2]net.Socket {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    if (!have_networking) return error.OperationUnsupported;
    if (@TypeOf(posix.system.socketpair) == void) return error.OperationUnsupported;
    if (native_os == .haiku) @panic("TODO");

    const family: posix.sa_family_t = switch (options.family) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const mode, const protocol = try posixSocketModeProtocol(family, options.mode, options.protocol);
    const flags: u32 = mode | if (socket_flags_unsupported) 0 else posix.SOCK.CLOEXEC;

    var sockets: [2]posix.socket_t = undefined;
    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.socketpair(family, flags, protocol, &sockets))) {
        .SUCCESS => {
            syscall.finish();
            errdefer {
                closeFd(sockets[0]);
                closeFd(sockets[1]);
            }
            if (socket_flags_unsupported) {
                try setCloexec(sockets[0]);
                try setCloexec(sockets[1]);
            }
            var storages: [2]PosixAddress = undefined;
            var addr_lens: [2]posix.socklen_t = .{ @sizeOf(PosixAddress), @sizeOf(PosixAddress) };
            try posixGetSockName(sockets[0], &storages[0].any, &addr_lens[0]);
            try posixGetSockName(sockets[1], &storages[1].any, &addr_lens[1]);
            return .{
                .{ .handle = sockets[0], .address = addressFromPosix(&storages[0]) },
                .{ .handle = sockets[1], .address = addressFromPosix(&storages[1]) },
            };
        },
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .ACCES => return syscall.fail(error.AccessDenied),
        .AFNOSUPPORT => return syscall.fail(error.AddressFamilyUnsupported),
        .INVAL => return syscall.fail(error.ProtocolUnsupportedBySystem),
        .MFILE => return syscall.fail(error.ProcessFdQuotaExceeded),
        .NFILE => return syscall.fail(error.SystemFdQuotaExceeded),
        .NOBUFS => return syscall.fail(error.SystemResources),
        .NOMEM => return syscall.fail(error.SystemResources),
        .PROTONOSUPPORT => return syscall.fail(error.ProtocolUnsupportedByAddressFamily),
        .PROTOTYPE => return syscall.fail(error.SocketModeUnsupported),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

pub fn netAcceptPosix(userdata: ?*anyopaque, listen_fd: net.Socket.Handle, options: net.Server.AcceptOptions) net.Server.AcceptError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    options;
    var storage: PosixAddress = undefined;
    var addr_len: posix.socklen_t = @sizeOf(PosixAddress);
    const syscall: Syscall = try .start();
    const fd = while (true) {
        const rc = if (have_accept4)
            posix.system.accept4(listen_fd, &storage.any, &addr_len, posix.SOCK.CLOEXEC)
        else
            posix.system.accept(listen_fd, &storage.any, &addr_len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const fd: posix.fd_t = @intCast(rc);
                errdefer closeFd(fd);
                if (!have_accept4) try setCloexec(fd);
                break fd;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .AGAIN => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNABORTED => return error.ConnectionAborted,
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.SocketNotListening,
                    .NOTSOCK => |err| return errnoBug(err),
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .OPNOTSUPP => |err| return errnoBug(err),
                    .PROTO => return error.ProtocolFailure,
                    .PERM => return error.BlockedByFirewall,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    };
    return .{ .handle = fd, .address = addressFromPosix(&storage) };
}

pub fn netRead(socket_handle: net.Socket.Handle, data: [][]u8, control: []u8) net.Stream.Reader.Error!net.Stream.ReadResult {
    if (!have_networking) return error.NetworkDown;

    if (is_windows) return .{ .data_len = try windows_impl.netReadWindows(socket_handle, data) };
    return netReadPosix(socket_handle, data, control);
}

pub fn netReadPosix(fd: net.Socket.Handle, data: [][]u8, control: []u8) net.Stream.Reader.Error!net.Stream.ReadResult {
    var iovecs_buffer: [max_iovecs_len]posix.iovec = undefined;
    var i: usize = 0;
    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    const dest = iovecs_buffer[0..i];
    assert(dest[0].len > 0);

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var n: usize = undefined;
            switch (std.os.wasi.fd_read(fd, dest.ptr, dest.len, &n)) {
                .SUCCESS => {
                    syscall.finish();
                    return .{ .data_len = n };
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
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .NOBUFS => return error.SystemResources,
                        .NOMEM => return error.SystemResources,
                        .NOTCONN => return error.SocketUnconnected,
                        .CONNRESET => return error.ConnectionResetByPeer,
                        .TIMEDOUT => return error.ConnectionTimedOut,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    var msg: posix.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = dest.ptr,
        .iovlen = @intCast(dest.len),
        .control = control.ptr,
        .controllen = @intCast(control.len),
        .flags = 0,
    };

    const flags: u32 =
        @as(u32, if (@hasDecl(posix.MSG, "CMSG_CLOEXEC")) posix.MSG.CMSG_CLOEXEC else 0);

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.recvmsg(fd, &msg, flags);
        const rc_control = msg.controllen;
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return .{
                    .data_len = @intCast(rc),
                    .control_len = @intCast(rc_control),
                    .control_truncated = (msg.flags & posix.MSG.CTRUNC) != 0,
                };
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
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTCONN => return error.SocketUnconnected,
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .TIMEDOUT => return error.ConnectionTimedOut,
                    .PIPE => return error.SocketUnconnected,
                    .NETDOWN => return error.NetworkDown,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn netSendPosix(
    t: *Threaded,
    socket_handle: net.Socket.Handle,
    messages: []net.OutgoingMessage,
    flags: net.SendFlags,
    nonblocking: bool,
) struct { ?(net.Socket.SendError || error{WouldBlock}), usize } {
    if (!have_networking) return .{ error.NetworkDown, 0 };

    const posix_flags: u32 =
        @as(u32, if (@hasDecl(posix.MSG, "CONFIRM") and flags.confirm) posix.MSG.CONFIRM else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "DONTROUTE") and flags.dont_route) posix.MSG.DONTROUTE else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "EOR") and flags.eor) posix.MSG.EOR else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "OOB") and flags.oob) posix.MSG.OOB else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "FASTOPEN") and flags.fastopen) posix.MSG.FASTOPEN else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "DONTWAIT") and nonblocking) posix.MSG.DONTWAIT else 0) |
        posix.MSG.NOSIGNAL;

    var i: usize = 0;
    while (messages.len - i != 0) {
        if (have_sendmmsg) {
            i += netSendManyPosix(socket_handle, messages[i..], posix_flags) catch |err| return .{ err, i };
            continue;
        }
        netSendOnePosix(t, socket_handle, &messages[i], posix_flags) catch |err| return .{ err, i };
        i += 1;
    }
    return .{ null, i };
}

pub fn netSendOnePosix(
    t: *Threaded,
    socket_handle: net.Socket.Handle,
    message: *net.OutgoingMessage,
    flags: u32,
) (net.Socket.SendError || error{WouldBlock})!void {
    _ = t;
    var addr: PosixAddress = undefined;
    var iovec: posix.iovec_const = .{ .base = @constCast(message.data_ptr), .len = message.data_len };
    const msg: posix.msghdr_const = .{
        .name = &addr.any,
        .namelen = addressToPosix(message.address, &addr),
        .iov = (&iovec)[0..1],
        .iovlen = 1,
        // OS returns EINVAL if this pointer is invalid even if controllen is zero.
        .control = if (message.control.len == 0) null else @constCast(message.control.ptr),
        .controllen = @intCast(message.control.len),
        .flags = 0,
    };
    var syscall: if (is_windows) AlertableSyscall else Syscall = try .start();
    while (true) {
        const rc = posix.system.sendmsg(socket_handle, &msg, flags);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                message.data_len = @intCast(rc);
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ACCES => return syscall.fail(error.AccessDenied),
            .AGAIN => return syscall.fail(error.WouldBlock),
            .ALREADY => return syscall.fail(error.FastOpenAlreadyInProgress),
            .CONNRESET => return syscall.fail(error.ConnectionResetByPeer),
            .MSGSIZE => return syscall.fail(error.MessageOversize),
            .NOBUFS => return syscall.fail(error.SystemResources),
            .NOMEM => return syscall.fail(error.SystemResources),
            .PIPE => return syscall.fail(error.SocketUnconnected),
            .AFNOSUPPORT => return syscall.fail(error.AddressFamilyUnsupported),
            .HOSTUNREACH => return syscall.fail(error.HostUnreachable),
            .NETUNREACH => return syscall.fail(error.NetworkUnreachable),
            .NOTCONN => return syscall.fail(error.SocketUnconnected),
            .TIMEDOUT => return syscall.fail(error.ConnectionTimedOut),
            .NETDOWN => return syscall.fail(error.NetworkDown),
            .BADF => |err| return syscall.errnoBug(err), // File descriptor used after closed.
            .DESTADDRREQ => |err| return syscall.errnoBug(err),
            .FAULT => |err| return syscall.errnoBug(err),
            .INVAL => |err| return syscall.errnoBug(err),
            .ISCONN => |err| return syscall.errnoBug(err),
            .NOTSOCK => |err| return syscall.errnoBug(err),
            .OPNOTSUPP => |err| return syscall.errnoBug(err),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

pub fn netSendManyPosix(
    socket_handle: net.Socket.Handle,
    messages: []net.OutgoingMessage,
    flags: u32,
) (net.Socket.SendError || error{WouldBlock})!usize {
    var msg_buffer: [64]posix.system.mmsghdr = undefined;
    var addr_buffer: [msg_buffer.len]PosixAddress = undefined;
    var iovecs_buffer: [msg_buffer.len]posix.iovec = undefined;
    const min_len: usize = @min(messages.len, msg_buffer.len);
    const clamped_messages = messages[0..min_len];
    const clamped_msgs = (&msg_buffer)[0..min_len];
    const clamped_addrs = (&addr_buffer)[0..min_len];
    const clamped_iovecs = (&iovecs_buffer)[0..min_len];

    for (clamped_messages, clamped_msgs, clamped_addrs, clamped_iovecs) |*message, *msg, *addr, *iovec| {
        iovec.* = .{ .base = @constCast(message.data_ptr), .len = message.data_len };
        msg.* = .{
            .hdr = .{
                .name = &addr.any,
                .namelen = addressToPosix(message.address, addr),
                .iov = iovec[0..1],
                .iovlen = 1,
                .control = @constCast(message.control.ptr),
                .controllen = message.control.len,
                .flags = 0,
            },
            .len = undefined, // Populated by calling sendmmsg below.
        };
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.sendmmsg(socket_handle, clamped_msgs.ptr, @intCast(clamped_msgs.len), flags);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const n: usize = @intCast(rc);
                for (clamped_messages[0..n], clamped_msgs[0..n]) |*message, *msg| {
                    message.data_len = msg.len;
                }
                return n;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ACCES => return syscall.fail(error.AccessDenied),
            .AGAIN => return syscall.fail(error.WouldBlock),
            .ALREADY => return syscall.fail(error.FastOpenAlreadyInProgress),
            .CONNRESET => return syscall.fail(error.ConnectionResetByPeer),
            .MSGSIZE => return syscall.fail(error.MessageOversize),
            .NOBUFS => return syscall.fail(error.SystemResources),
            .NOMEM => return syscall.fail(error.SystemResources),
            .PIPE => return syscall.fail(error.SocketUnconnected),
            .AFNOSUPPORT => return syscall.fail(error.AddressFamilyUnsupported),
            .HOSTUNREACH => return syscall.fail(error.HostUnreachable),
            .NETUNREACH => return syscall.fail(error.NetworkUnreachable),
            .NOTCONN => return syscall.fail(error.SocketUnconnected),
            .TIMEDOUT => return syscall.fail(error.ConnectionTimedOut),
            .NETDOWN => return syscall.fail(error.NetworkDown),

            .BADF => |err| return syscall.errnoBug(err), // File descriptor used after closed.
            .DESTADDRREQ => |err| return syscall.errnoBug(err), // The socket is not connection-mode, and no peer address is set.
            .FAULT => |err| return syscall.errnoBug(err), // An invalid user space address was specified for an argument.
            .INVAL => |err| return syscall.errnoBug(err), // Invalid argument passed.
            .ISCONN => |err| return syscall.errnoBug(err), // connection-mode socket was connected already but a recipient was specified
            .NOTSOCK => |err| return syscall.errnoBug(err), // The file descriptor sockfd does not refer to a socket.
            .OPNOTSUPP => |err| return syscall.errnoBug(err), // Some bit in the flags argument is inappropriate for the socket type.

            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

pub fn netReceivePosix(
    socket_handle: net.Socket.Handle,
    message: *net.IncomingMessage,
    data_buffer: []u8,
    flags: net.ReceiveFlags,
    nonblocking: bool,
) (net.Socket.ReceiveError || error{WouldBlock})!void {
    // recvmmsg is useless, here's why:
    // * [timeout bug](https://bugzilla.kernel.org/show_bug.cgi?id=75371)
    // * it wants iovecs for each message but we have a better API: one data
    //   buffer to handle all the messages. The better API cannot be lowered to
    //   the split vectors though because reducing the buffer size might make
    //   some messages unreceivable.
    const posix_flags: u32 =
        @as(u32, if (flags.oob) posix.MSG.OOB else 0) |
        @as(u32, if (flags.peek) posix.MSG.PEEK else 0) |
        @as(u32, if (flags.trunc) posix.MSG.TRUNC else 0) |
        @as(u32, if (nonblocking) posix.MSG.DONTWAIT else 0);

    var storage: PosixAddress = undefined;
    var iov: posix.iovec = .{ .base = data_buffer.ptr, .len = data_buffer.len };
    var msg: posix.msghdr = .{
        .name = &storage.any,
        .namelen = @sizeOf(PosixAddress),
        .iov = (&iov)[0..1],
        .iovlen = 1,
        .control = message.control.ptr,
        .controllen = @intCast(message.control.len),
        .flags = 0,
    };

    const syscall = try Syscall.start();
    while (true) {
        const rc = posix.system.recvmsg(socket_handle, &msg, posix_flags);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const data = data_buffer[0..@intCast(rc)];
                message.* = .{
                    .from = addressFromPosix(&storage),
                    .data = data,
                    .control = if (msg.control) |ptr| @as([*]u8, @ptrCast(ptr))[0..msg.controllen] else message.control,
                    .flags = .{
                        .eor = (msg.flags & posix.MSG.EOR) != 0,
                        .trunc = (msg.flags & posix.MSG.TRUNC) != 0,
                        .ctrunc = (msg.flags & posix.MSG.CTRUNC) != 0,
                        .oob = (msg.flags & posix.MSG.OOB) != 0,
                        .errqueue = if (@hasDecl(posix.MSG, "ERRQUEUE")) (msg.flags & posix.MSG.ERRQUEUE) != 0 else false,
                    },
                };
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .NFILE => return syscall.fail(error.SystemFdQuotaExceeded),
            .MFILE => return syscall.fail(error.ProcessFdQuotaExceeded),
            .NOBUFS => return syscall.fail(error.SystemResources),
            .NOMEM => return syscall.fail(error.SystemResources),
            .NOTCONN => return syscall.fail(error.SocketUnconnected),
            .MSGSIZE => return syscall.fail(error.MessageOversize),
            .PIPE => return syscall.fail(error.SocketUnconnected),
            .CONNRESET => return syscall.fail(error.ConnectionResetByPeer),
            .TIMEDOUT => return syscall.fail(error.ConnectionTimedOut),
            .NETDOWN => return syscall.fail(error.NetworkDown),
            .AGAIN => return syscall.fail(error.WouldBlock),
            .BADF => |err| return syscall.errnoBug(err),
            .FAULT => |err| return syscall.errnoBug(err),
            .INVAL => |err| return syscall.errnoBug(err),
            .NOTSOCK => |err| return syscall.errnoBug(err),
            .OPNOTSUPP => |err| return syscall.errnoBug(err),
            else => |err| return syscall.unexpectedErrno(err),
        }
    }
}

pub fn netWritePosix(
    fd: net.Socket.Handle,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
    control: []const u8,
) net.Stream.Writer.Error!usize {
    if (!have_networking) return error.NetworkDown;

    var iovecs: [max_iovecs_len]posix.iovec_const = undefined;
    var msg: posix.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iovecs,
        .iovlen = 0,
        .control = if (control.len == 0) null else @constCast(control.ptr),
        .controllen = @intCast(control.len),
        .flags = 0,
    };
    addBuf(&iovecs, &msg.iovlen, header);
    for (data[0 .. data.len - 1]) |bytes| addBuf(&iovecs, &msg.iovlen, bytes);
    const pattern = data[data.len - 1];

    var splat_backup_buffer: [splat_buffer_size]u8 = undefined;
    if (iovecs.len - msg.iovlen != 0) switch (splat) {
        0 => {},
        1 => addBuf(&iovecs, &msg.iovlen, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                const splat_buffer = &splat_backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addBuf(&iovecs, &msg.iovlen, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - msg.iovlen != 0) {
                    assert(buf.len == splat_buffer.len);
                    addBuf(&iovecs, &msg.iovlen, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addBuf(&iovecs, &msg.iovlen, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - msg.iovlen)) |_| {
                addBuf(&iovecs, &msg.iovlen, pattern);
            },
        },
    };
    const flags = posix.MSG.NOSIGNAL;

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.sendmsg(fd, &msg, flags);
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
                    .ACCES => |err| return errnoBug(err),
                    .AGAIN => |err| return errnoBug(err),
                    .ALREADY => return error.FastOpenAlreadyInProgress,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .DESTADDRREQ => |err| return errnoBug(err), // The socket is not connection-mode, and no peer address is set.
                    .FAULT => |err| return errnoBug(err), // An invalid user space address was specified for an argument.
                    .INVAL => |err| return errnoBug(err), // Invalid argument passed.
                    .ISCONN => |err| return errnoBug(err), // connection-mode socket was connected already but a recipient was specified
                    .MSGSIZE => |err| return errnoBug(err),
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTSOCK => |err| return errnoBug(err), // The file descriptor sockfd does not refer to a socket.
                    .OPNOTSUPP => |err| return errnoBug(err), // Some bit in the flags argument is inappropriate for the socket type.
                    .PIPE => return error.SocketUnconnected,
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .HOSTUNREACH => return error.HostUnreachable,
                    .NETUNREACH => return error.NetworkUnreachable,
                    .NOTCONN => return error.SocketUnconnected,
                    .TIMEDOUT => return error.ConnectionTimedOut,
                    .NETDOWN => return error.NetworkDown,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn netClose(userdata: ?*anyopaque, sockets: []const net.Socket) void {
    if (!have_networking) unreachable;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    for (sockets) |socket| switch (native_os) {
        .windows => windows.CloseHandle(socket.handle),
        else => closeFd(socket.handle),
    };
}

pub fn netShutdownPosix(userdata: ?*anyopaque, handle: net.Socket.Handle, how: net.ShutdownHow) net.ShutdownError!void {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const posix_how: i32 = switch (how) {
        .recv => posix.SHUT.RD,
        .send => posix.SHUT.WR,
        .both => posix.SHUT.RDWR,
    };

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.shutdown(handle, posix_how))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF, .NOTSOCK, .INVAL => |err| return errnoBug(err),
                    .NOTCONN => return error.SocketUnconnected,
                    .NOBUFS => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn netInterfaceNameResolve(
    userdata: ?*anyopaque,
    name: *const net.Interface.Name,
) net.Interface.Name.ResolveError!net.Interface {
    if (!have_networking) return error.InterfaceNotFound;
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    if (native_os == .linux) {
        const sock_fd = openSocketPosix(posix.AF.UNIX, .{ .mode = .dgram }) catch |err| switch (err) {
            error.ProcessFdQuotaExceeded => return error.SystemResources,
            error.SystemFdQuotaExceeded => return error.SystemResources,
            error.AddressFamilyUnsupported => return error.Unexpected,
            error.ProtocolUnsupportedBySystem => return error.Unexpected,
            error.ProtocolUnsupportedByAddressFamily => return error.Unexpected,
            error.SocketModeUnsupported => return error.Unexpected,
            error.OptionUnsupported => return error.Unexpected,
            else => |e| return e,
        };
        defer closeFd(sock_fd);

        var ifr: posix.ifreq = .{
            .ifrn = .{ .name = @bitCast(name.bytes) },
            .ifru = undefined,
        };

        const syscall: Syscall = try .start();
        while (true) switch (posix.errno(posix.system.ioctl(sock_fd, posix.SIOCGIFINDEX, @intFromPtr(&ifr)))) {
            .SUCCESS => {
                syscall.finish();
                return .{ .index = @bitCast(ifr.ifru.ivalue) };
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .NODEV => return syscall.fail(error.InterfaceNotFound),
            else => |err| return syscall.unexpectedErrno(err),
        };
    }

    if (is_windows) {
        var ConvertInterfaceNameToLuidW = t.dl.ConvertInterfaceNameToLuidW.load(.acquire);
        var ConvertInterfaceLuidToIndex = t.dl.ConvertInterfaceLuidToIndex.load(.acquire);
        if (ConvertInterfaceNameToLuidW == null or ConvertInterfaceLuidToIndex == null) {
            const iphlpapi_dll = t.dl.iphlpapi_dll.load(.acquire) orelse iphlpapi_dll: {
                try Thread.checkCancel();
                var iphlpapi_dll: *anyopaque = undefined;
                switch (windows.ntdll.LdrLoadDll(null, null, &.init(
                    &.{ 'I', 'P', 'H', 'L', 'P', 'A', 'P', 'I', '.', 'D', 'L', 'L' },
                ), &iphlpapi_dll)) {
                    .SUCCESS => {},
                    .DLL_NOT_FOUND => return error.Unexpected,
                    else => |status| return windows.unexpectedStatus(status),
                }
                const handle = t.dl.iphlpapi_dll.cmpxchgStrong(null, iphlpapi_dll, .release, .monotonic) orelse
                    break :iphlpapi_dll iphlpapi_dll;
                switch (windows.ntdll.LdrUnloadDll(iphlpapi_dll)) {
                    .SUCCESS => break :iphlpapi_dll handle.?,
                    else => |status| return windows.unexpectedStatus(status),
                }
            };
            switch (windows.ntdll.LdrGetProcedureAddress(iphlpapi_dll, &.init(
                &.{
                    'C', 'o', 'n', 'v', 'e', 'r', 't', 'I', 'n', 't', 'e', 'r', 'f', 'a', 'c', 'e',
                    'N', 'a', 'm', 'e', 'T', 'o', 'L', 'u', 'i', 'd', 'W',
                },
            ), 0, @ptrCast(&ConvertInterfaceNameToLuidW))) {
                .SUCCESS => t.dl.ConvertInterfaceNameToLuidW.store(ConvertInterfaceNameToLuidW, .release),
                else => |status| return windows.unexpectedStatus(status),
            }
            switch (windows.ntdll.LdrGetProcedureAddress(iphlpapi_dll, &.init(
                &.{
                    'C', 'o', 'n', 'v', 'e', 'r', 't', 'I', 'n', 't', 'e', 'r', 'f', 'a', 'c', 'e',
                    'L', 'u', 'i', 'd', 'T', 'o', 'I', 'n', 'd', 'e', 'x',
                },
            ), 0, @ptrCast(&ConvertInterfaceLuidToIndex))) {
                .SUCCESS => t.dl.ConvertInterfaceLuidToIndex.store(ConvertInterfaceLuidToIndex, .release),
                else => |status| return windows.unexpectedStatus(status),
            }
        }
        try Thread.checkCancel();
        var name_w: [net.Interface.Name.max_len:0]windows.WCHAR = undefined;
        name_w[
            std.unicode.wtf8ToWtf16Le(&name_w, name.toSlice()) catch |err| switch (err) {
                error.InvalidWtf8 => return error.InterfaceNotFound,
            }
        ] = 0;
        var luid: windows.NET.LUID = undefined;
        switch (ConvertInterfaceNameToLuidW.?(&name_w, &luid)) {
            .SUCCESS => {},
            .INVALID_NAME => return error.InterfaceNotFound,
            .INVALID_PARAMETER => unreachable,
            else => |err| return windows.unexpectedError(err),
        }
        var index: windows.NET.IFINDEX = undefined;
        switch (ConvertInterfaceLuidToIndex.?(&luid, &index)) {
            .SUCCESS => {},
            .INVALID_PARAMETER => unreachable,
            else => |err| return windows.unexpectedError(err),
        }
        return .{ .index = @backingInt(index) };
    }

    if (builtin.link_libc) {
        try Thread.checkCancel();
        const index = std.c.if_nametoindex(&name.bytes);
        if (index == 0) return error.InterfaceNotFound;
        return .{ .index = @bitCast(index) };
    }

    @panic("unimplemented");
}

pub fn netInterfaceName(userdata: ?*anyopaque, interface: net.Interface) net.Interface.NameError!net.Interface.Name {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    if (native_os == .linux) {
        try Thread.checkCancel();
        @panic("TODO implement netInterfaceName for linux");
    }

    if (is_windows) {
        var ConvertInterfaceIndexToLuid = t.dl.ConvertInterfaceIndexToLuid.load(.acquire);
        var ConvertInterfaceLuidToNameW = t.dl.ConvertInterfaceLuidToNameW.load(.acquire);
        if (ConvertInterfaceIndexToLuid == null or ConvertInterfaceLuidToNameW == null) {
            const iphlpapi_dll = t.dl.iphlpapi_dll.load(.acquire) orelse iphlpapi_dll: {
                try Thread.checkCancel();
                var iphlpapi_dll: *anyopaque = undefined;
                switch (windows.ntdll.LdrLoadDll(null, null, &.init(
                    &.{ 'I', 'P', 'H', 'L', 'P', 'A', 'P', 'I', '.', 'D', 'L', 'L' },
                ), &iphlpapi_dll)) {
                    .SUCCESS => {},
                    .DLL_NOT_FOUND => return error.Unexpected,
                    else => |status| return windows.unexpectedStatus(status),
                }
                const handle = t.dl.iphlpapi_dll.cmpxchgStrong(null, iphlpapi_dll, .release, .monotonic) orelse
                    break :iphlpapi_dll iphlpapi_dll;
                switch (windows.ntdll.LdrUnloadDll(iphlpapi_dll)) {
                    .SUCCESS => break :iphlpapi_dll handle.?,
                    else => |status| return windows.unexpectedStatus(status),
                }
            };
            switch (windows.ntdll.LdrGetProcedureAddress(iphlpapi_dll, &.init(
                &.{
                    'C', 'o', 'n', 'v', 'e', 'r', 't', 'I', 'n', 't', 'e', 'r', 'f', 'a', 'c', 'e',
                    'I', 'n', 'd', 'e', 'x', 'T', 'o', 'L', 'u', 'i', 'd',
                },
            ), 0, @ptrCast(&ConvertInterfaceIndexToLuid))) {
                .SUCCESS => t.dl.ConvertInterfaceIndexToLuid.store(ConvertInterfaceIndexToLuid, .release),
                else => |status| return windows.unexpectedStatus(status),
            }
            switch (windows.ntdll.LdrGetProcedureAddress(iphlpapi_dll, &.init(
                &.{
                    'C', 'o', 'n', 'v', 'e', 'r', 't', 'I', 'n', 't', 'e', 'r', 'f', 'a', 'c', 'e',
                    'L', 'u', 'i', 'd', 'T', 'o', 'N', 'a', 'm', 'e', 'W',
                },
            ), 0, @ptrCast(&ConvertInterfaceLuidToNameW))) {
                .SUCCESS => t.dl.ConvertInterfaceLuidToNameW.store(ConvertInterfaceLuidToNameW, .release),
                else => |status| return windows.unexpectedStatus(status),
            }
        }
        try Thread.checkCancel();
        var luid: windows.NET.LUID = undefined;
        switch (ConvertInterfaceIndexToLuid.?(@fromBackingInt(@intCast(interface.index)), &luid)) {
            .SUCCESS => {},
            .FILE_NOT_FOUND => return error.InterfaceNotFound,
            .INVALID_PARAMETER => unreachable,
            else => |err| return windows.unexpectedError(err),
        }
        var name_w: [net.Interface.Name.max_len:0]windows.WCHAR = undefined;
        switch (ConvertInterfaceLuidToNameW.?(&luid, &name_w, name_w.len)) {
            .SUCCESS => {},
            .INVALID_PARAMETER => unreachable,
            .NOT_ENOUGH_MEMORY => return error.NameTooLong,
            else => |err| return windows.unexpectedError(err),
        }
        var name: [3 * net.Interface.Name.max_len]u8 = undefined;
        return .fromSlice(name[0..std.unicode.wtf16LeToWtf8(&name, std.mem.sliceTo(&name_w, 0))]);
    }

    if (builtin.link_libc) {
        try Thread.checkCancel();
        @panic("TODO implement netInterfaceName for libc");
    }

    @panic("unimplemented");
}

pub fn netLookup(
    userdata: ?*anyopaque,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) net.HostName.LookupError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    defer resolved.close(io(t));
    netLookupFallible(t, host_name, resolved, options) catch |err| switch (err) {
        error.Closed => unreachable, // `resolved` must not be closed until `netLookup` returns
        else => |e| return e,
    };
}

pub fn netLookupFallible(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) (net.HostName.LookupError || Io.QueueClosedError)!void {
    if (!have_networking) return error.NetworkDown;

    const t_io = t.io();
    const name = host_name.bytes;
    assert(name.len <= HostName.max_len);

    // On Linux, glibc provides getaddrinfo_a which is capable of supporting our semantics.
    // However, musl's POSIX-compliant getaddrinfo is not, so we bypass it.
    const is_glibc = builtin.link_libc and builtin.target.isGnuLibC();

    if (is_glibc) {
        // TODO use getaddrinfo_a / gai_cancel
    }

    // On Linux, we have to go through glibc because of the Name Service Switch feature.
    const non_glibc_linux = native_os == .linux and !is_glibc;
    if (non_glibc_linux or is_windows) {
        if (IpAddress.parseIp6(name, options.port)) |addr| {
            if (options.family == .ip4) return error.UnknownHostName;
            if (copyCanon(options.canonical_name_buffer, name)) |canon| {
                try resolved.putAll(t_io, &.{
                    .{ .address = addr },
                    .{ .canonical_name = canon },
                });
            } else {
                try resolved.putOne(t_io, .{ .address = addr });
            }
            return;
        } else |_| {}

        if (IpAddress.parseIp4(name, options.port)) |addr| {
            if (options.family == .ip6) return error.UnknownHostName;
            if (copyCanon(options.canonical_name_buffer, name)) |canon| {
                try resolved.putAll(t_io, &.{
                    .{ .address = addr },
                    .{ .canonical_name = canon },
                });
            } else {
                try resolved.putOne(t_io, .{ .address = addr });
            }
            return;
        } else |_| {}

        if (lookupHosts(t, host_name, resolved, options)) return else |err| switch (err) {
            error.UnknownHostName => {},
            else => |e| return e,
        }

        // RFC 6761 Section 6.3.3
        // Name resolution APIs and libraries SHOULD recognize
        // localhost names as special and SHOULD always return the IP
        // loopback address for address queries and negative responses
        // for all other query types.

        // Check for equal to "localhost(.)" or ends in ".localhost(.)"
        const localhost = if (name[name.len - 1] == '.') "localhost." else "localhost";
        if (std.mem.endsWith(u8, name, localhost) and
            (name.len == localhost.len or name[name.len - localhost.len - 1] == '.'))
        {
            var results_buffer: [3]HostName.LookupResult = undefined;
            var results_index: usize = 0;
            if (options.family != .ip4) {
                results_buffer[results_index] = .{ .address = .{ .ip6 = .loopback(options.port) } };
                results_index += 1;
            }
            if (options.family != .ip6) {
                results_buffer[results_index] = .{ .address = .{ .ip4 = .loopback(options.port) } };
                results_index += 1;
            }
            if (options.canonical_name_buffer) |buf| {
                const canon_name = "localhost";
                const canon_name_dest = buf[0..canon_name.len];
                canon_name_dest.* = canon_name.*;
                results_buffer[results_index] = .{ .canonical_name = .{ .bytes = canon_name_dest } };
                results_index += 1;
            }
            try resolved.putAll(t_io, results_buffer[0..results_index]);
            return;
        }

        if (native_os == .linux) return lookupDnsSearch(t, host_name, resolved, options);

        comptime assert(is_windows);
        var DnsQueryEx = t.dl.DnsQueryEx.load(.acquire);
        //var DnsCancelQuery = t.dl.DnsCancelQuery.load(.acquire);
        var DnsFree = t.dl.DnsFree.load(.acquire);
        if (DnsQueryEx == null or
            //DnsCancelQuery == null or
            DnsFree == null)
        {
            const dnsapi_dll = t.dl.dnsapi_dll.load(.acquire) orelse dnsapi_dll: {
                try Thread.checkCancel();
                var dnsapi_dll: *anyopaque = undefined;
                switch (windows.ntdll.LdrLoadDll(null, null, &.init(
                    &.{ 'd', 'n', 's', 'a', 'p', 'i', '.', 'd', 'l', 'l' },
                ), &dnsapi_dll)) {
                    .SUCCESS => {},
                    .DLL_NOT_FOUND => return error.Unexpected,
                    else => |status| return windows.unexpectedStatus(status),
                }
                const handle = t.dl.dnsapi_dll.cmpxchgStrong(null, dnsapi_dll, .release, .monotonic) orelse
                    break :dnsapi_dll dnsapi_dll;
                switch (windows.ntdll.LdrUnloadDll(dnsapi_dll)) {
                    .SUCCESS => break :dnsapi_dll handle.?,
                    else => |status| return windows.unexpectedStatus(status),
                }
            };
            switch (windows.ntdll.LdrGetProcedureAddress(dnsapi_dll, &.init(
                &.{ 'D', 'n', 's', 'Q', 'u', 'e', 'r', 'y', 'E', 'x' },
            ), 0, @ptrCast(&DnsQueryEx))) {
                .SUCCESS => t.dl.DnsQueryEx.store(DnsQueryEx, .release),
                else => |status| return windows.unexpectedStatus(status),
            }
            //switch (windows.ntdll.LdrGetProcedureAddress(dnsapi_dll, &.init(
            //    &.{ 'D', 'n', 's', 'C', 'a', 'n', 'c', 'e', 'l', 'Q', 'u', 'e', 'r', 'y' },
            //), 0, @ptrCast(&DnsCancelQuery))) {
            //    .SUCCESS => t.dl.DnsCancelQuery.store(DnsCancelQuery, .release),
            //    else => |status| return windows.unexpectedStatus(status),
            //}
            switch (windows.ntdll.LdrGetProcedureAddress(dnsapi_dll, &.init(
                &.{ 'D', 'n', 's', 'F', 'r', 'e', 'e' },
            ), 0, @ptrCast(&DnsFree))) {
                .SUCCESS => t.dl.DnsFree.store(DnsFree, .release),
                else => |status| return windows.unexpectedStatus(status),
            }
        }
        try Thread.checkCancel();
        const current_thread = Thread.current;
        var lookup_dns: windows_impl.LookupDnsWindows = .{
            .threaded = t,
            .thread = if (current_thread) |thread| thread.handle else undefined,
            .resolved = resolved,
            .options = options,
            .results = .{
                .Version = 1,
                .QueryStatus = undefined,
                .QueryOptions = undefined,
                .pQueryRecords = undefined,
                .Reserved = undefined,
            },
            .done = false,
        };
        var host_name_w: [HostName.max_len:0]windows.WCHAR = undefined;
        host_name_w[
            std.unicode.wtf8ToWtf16Le(&host_name_w, name) catch |err| switch (err) {
                error.InvalidWtf8 => return error.UnknownHostName,
            }
        ] = 0;
        //var cancel_token: windows.DNS.QUERY.CANCEL = undefined;
        // Workaround various bugs by attempting a synchronous non-wire query first
        switch (DnsQueryEx.?(&.{
            .Version = 1,
            .QueryName = &host_name_w,
            .QueryType = if (options.family == .ip4) .A else .AAAA,
            .QueryOptions = .{
                .NO_WIRE_QUERY = true,
                .NO_HOSTS_FILE = true, // handled above
                .ADDRCONFIG = true,
                .DUAL_ADDR = options.family == null,
            },
        }, &lookup_dns.results, null)) {
            .SUCCESS => try lookup_dns.completedFallible(),
            // We must wait for the APC routine.
            .DNS_REQUEST_PENDING => unreachable, // `pQueryCompletionCallback` was `null`
            .DNS_ERROR_RECORD_DOES_NOT_EXIST => switch (DnsQueryEx.?(&.{
                .Version = 1,
                .QueryName = &host_name_w,
                .QueryType = if (options.family == .ip4) .A else .AAAA,
                .QueryOptions = .{
                    .NO_HOSTS_FILE = true, // handled above
                    .ADDRCONFIG = true,
                    .DUAL_ADDR = options.family == null,
                    .MULTICAST_WAIT = true,
                },
                .pQueryCompletionCallback = if (current_thread) |_| &windows_impl.LookupDnsWindows.completed else null,
            }, &lookup_dns.results,
                //&cancel_token,
                null)) {
                .SUCCESS => try lookup_dns.completedFallible(),
                // We must wait for the APC routine.
                .DNS_REQUEST_PENDING => {
                    assert(current_thread != null); // `pQueryCompletionCallback` was `null`
                    while (!@atomicLoad(bool, &lookup_dns.done, .acquire)) {
                        // Once we get here we must not return from the function until the
                        // operation completes, thereby releasing references to `host_name_w`,
                        // `lookup_dns.results`, and `cancel_token`.
                        const alertable_syscall = AlertableSyscall.start() catch |err| switch (err) {
                            error.Canceled => |e| {
                                //_ = DnsCancelQuery.?(&cancel_token);
                                while (!@atomicLoad(bool, &lookup_dns.done, .acquire)) waitForApcOrAlert();
                                return e;
                            },
                        };
                        waitForApcOrAlert();
                        alertable_syscall.finish();
                    }
                },
                else => |status| lookup_dns.results.QueryStatus = status,
            },
            else => |status| lookup_dns.results.QueryStatus = status,
        }
        switch (lookup_dns.results.QueryStatus) {
            .SUCCESS => return,
            .DNS_REQUEST_PENDING => unreachable, // already handled
            .INVALID_NAME,
            .DNS_ERROR_RCODE_NAME_ERROR,
            .DNS_INFO_NO_RECORDS,
            .DNS_ERROR_INVALID_NAME_CHAR,
            .DNS_ERROR_RECORD_DOES_NOT_EXIST,
            => return error.UnknownHostName,
            .TIMEOUT => return error.NameServerFailure,
            else => |err| return windows.unexpectedError(err),
        }
    }

    if (native_os == .openbsd) {
        // TODO use getaddrinfo_async / asr_abort
    }

    if (native_os == .freebsd) {
        // TODO use dnsres_getaddrinfo
    }

    if (is_darwin) {
        // TODO use CFHostStartInfoResolution / CFHostCancelInfoResolution
    }

    if (builtin.link_libc) {
        // This operating system lacks a way to resolve asynchronously. We are
        // stuck with getaddrinfo.
        var name_buffer: [HostName.max_len:0]u8 = undefined;
        @memcpy(name_buffer[0..name.len], name);
        name_buffer[name.len] = 0;
        const name_c = name_buffer[0..name.len :0];

        var port_buffer: [8]u8 = undefined;
        const port_c = std.mem.printSentinel(&port_buffer, "{d}", .{options.port}, 0) catch unreachable;

        const family: i32 = if (options.family) |f| switch (f) {
            .ip4 => posix.AF.INET,
            .ip6 => posix.AF.INET6,
        } else posix.AF.UNSPEC;

        const hints: posix.addrinfo = .{
            .flags = .{ .CANONNAME = options.canonical_name_buffer != null, .NUMERICSERV = true },
            .family = family,
            .socktype = posix.SOCK.STREAM,
            .protocol = posix.IPPROTO.TCP,
            .canonname = null,
            .addr = null,
            .addrlen = 0,
            .next = null,
        };
        var res: ?*posix.addrinfo = null;
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.system.getaddrinfo(name_c.ptr, port_c.ptr, &hints, &res)) {
                @as(posix.system.EAI, @fromBackingInt(@intCast(0))) => {
                    syscall.finish();
                    break;
                },
                .SYSTEM => switch (posix.errno(-1)) {
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        return posix.unexpectedErrno(e);
                    },
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ADDRFAMILY => return error.AddressFamilyUnsupported,
                        .AGAIN => return error.NameServerFailure,
                        .FAIL => return error.NameServerFailure,
                        .FAMILY => return error.AddressFamilyUnsupported,
                        .MEMORY => return error.SystemResources,
                        .NODATA => return error.UnknownHostName,
                        .NONAME => return error.UnknownHostName,
                        else => return error.Unexpected,
                    }
                },
            }
        }
        defer if (res) |some| posix.system.freeaddrinfo(some);

        var it = res;
        var canon_name: ?[*:0]const u8 = null;
        while (it) |info| : (it = info.next) {
            const addr = info.addr orelse continue;
            try resolved.putOne(t_io, .{ .address = addressFromPosix(@alignCast(@fieldParentPtr("any", addr))) });

            if (info.canonname) |n| {
                if (canon_name == null) {
                    canon_name = n;
                }
            }
        }
        if (canon_name) |n| {
            if (copyCanon(options.canonical_name_buffer, std.mem.sliceTo(n, 0))) |canon| {
                try resolved.putOne(t_io, .{ .canonical_name = canon });
            }
        }
        return;
    }

    return error.OptionUnsupported;
}

pub fn lookupDnsSearch(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) (HostName.LookupError || Io.QueueClosedError)!void {
    const t_io = io(t);
    const rc = HostName.ResolvConf.init(t_io) catch return error.ResolvConfParseFailed;

    // Count dots, suppress search when >=ndots or name ends in
    // a dot, which is an explicit request for global scope.
    const dots = std.mem.countScalar(u8, host_name.bytes, '.');
    const search_len = if (dots >= rc.ndots or std.mem.endsWith(u8, host_name.bytes, ".")) 0 else rc.search_len;
    const search = rc.search_buffer[0..search_len];

    var canon_name = host_name.bytes;

    // Strip final dot for canon, fail if multiple trailing dots.
    if (std.mem.endsWith(u8, canon_name, ".")) canon_name.len -= 1;
    if (std.mem.endsWith(u8, canon_name, ".")) return error.UnknownHostName;

    // Name with search domain appended is set up in `canon_name`. This
    // both provides the desired default canonical name (if the requested
    // name is not a CNAME record) and serves as a buffer for passing the
    // full requested name to `lookupDns`.
    var local_buf: [HostName.max_len]u8 = undefined;
    const canon_buf = options.canonical_name_buffer orelse &local_buf;
    @memcpy(canon_buf[0..canon_name.len], canon_name);
    canon_buf[canon_name.len] = '.';
    var it = std.mem.tokenizeAny(u8, search, " \t");
    while (it.next()) |token| {
        @memcpy(canon_buf[canon_name.len + 1 ..][0..token.len], token);
        const lookup_canon_name = canon_buf[0 .. canon_name.len + 1 + token.len];
        if (lookupDns(t, lookup_canon_name, &rc, resolved, options)) |result| {
            return result;
        } else |err| switch (err) {
            error.UnknownHostName, error.NoAddressReturned => continue,
            else => |e| return e,
        }
    }

    const lookup_canon_name = canon_buf[0..canon_name.len];
    return lookupDns(t, lookup_canon_name, &rc, resolved, options);
}

pub fn lookupDns(
    t: *Threaded,
    lookup_canon_name: []const u8,
    rc: *const HostName.ResolvConf,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) (HostName.LookupError || Io.QueueClosedError)!void {
    const t_io = io(t);
    const family_records: [2]struct { af: IpAddress.Family, rr: HostName.DnsRecord } = .{
        .{ .af = .ip6, .rr = .A },
        .{ .af = .ip4, .rr = .AAAA },
    };
    var query_buffers: [2][280]u8 = undefined;
    var answer_buffer: [2 * 512]u8 = undefined;
    var queries_buffer: [2][]const u8 = undefined;
    var answers_buffer: [2][]const u8 = undefined;
    var nq: usize = 0;
    var answer_buffer_i: usize = 0;

    for (family_records) |fr| {
        if (options.family != fr.af) {
            var entropy: [2]u8 = undefined;
            random(t, &entropy);
            const len = writeResolutionQuery(&query_buffers[nq], 0, lookup_canon_name, 1, fr.rr, entropy);
            queries_buffer[nq] = query_buffers[nq][0..len];
            nq += 1;
        }
    }

    var ip4_mapped_buffer: [HostName.ResolvConf.max_nameservers]IpAddress = undefined;
    const ip4_mapped = ip4_mapped_buffer[0..rc.nameservers_len];
    var any_ip6 = false;
    for (rc.nameservers(), ip4_mapped) |*ns, *m| {
        m.* = .{ .ip6 = .fromAny(ns.*) };
        any_ip6 = any_ip6 or ns.* == .ip6;
    }
    var socket = s: {
        if (any_ip6) ip6: {
            const ip6_addr: IpAddress = .{ .ip6 = .unspecified(0) };
            const socket = ip6_addr.bind(t_io, .{ .ip6_only = false, .mode = .dgram }) catch |err| switch (err) {
                error.AddressFamilyUnsupported => break :ip6,
                else => |e| return e,
            };
            break :s socket;
        }
        any_ip6 = false;
        const ip4_addr: IpAddress = .{ .ip4 = .unspecified(0) };
        const socket = try ip4_addr.bind(t_io, .{ .mode = .dgram });
        break :s socket;
    };
    defer socket.close(t_io);

    const mapped_nameservers = if (any_ip6) ip4_mapped else rc.nameservers();
    const queries = queries_buffer[0..nq];
    const answers = answers_buffer[0..queries.len];
    var answers_remaining = answers.len;
    for (answers) |*answer| answer.len = 0;

    // boot clock is chosen because time the computer is suspended should count
    // against time spent waiting for external messages to arrive.
    const clock: Io.Clock = .boot;
    var now_ts = clock.now(t_io);
    const final_ts = now_ts.addDuration(.fromSeconds(rc.timeout_seconds));
    const attempt_duration: Io.Duration = .{
        .nanoseconds = (std.time.ns_per_s / rc.attempts) * @as(i96, rc.timeout_seconds),
    };

    send: while (now_ts.nanoseconds < final_ts.nanoseconds) : (now_ts = clock.now(t_io)) {
        const timeout: Io.Timeout = .{ .deadline = .{
            .raw = now_ts.addDuration(attempt_duration),
            .clock = clock,
        } };

        const max_messages = queries_buffer.len * HostName.ResolvConf.max_nameservers;
        {
            var message_buffer: [max_messages]net.OutgoingMessage = undefined;
            var message_i: usize = 0;
            for (queries, answers) |query, *answer| {
                if (answer.len != 0) continue;
                for (mapped_nameservers) |*ns| {
                    message_buffer[message_i] = .{
                        .address = ns,
                        .data_ptr = query.ptr,
                        .data_len = query.len,
                    };
                    message_i += 1;
                }
            }
            const send_err, _ = socket.sendManyTimeout(t_io, message_buffer[0..message_i], .{}, timeout);
            if (send_err) |err| switch (err) {
                error.Canceled => |e| return e,
                error.Timeout => continue :send,
                else => {},
            };
        }

        while (true) {
            var message_buffer: [max_messages]net.IncomingMessage = @splat(.init);
            const buf = answer_buffer[answer_buffer_i..];
            const recv_err, const recv_n = socket.receiveManyTimeout(t_io, &message_buffer, buf, .{}, timeout);
            for (message_buffer[0..recv_n]) |*received_message| {
                const reply = received_message.data;
                // Ignore non-identifiable packets.
                if (reply.len < 4) continue;

                // Ignore replies from addresses we didn't send to.
                const ns = for (mapped_nameservers) |*ns| {
                    if (received_message.from.eql(ns)) break ns;
                } else {
                    continue;
                };

                // Find which query this answer goes with, if any.
                const query, const answer = for (queries, answers) |query, *answer| {
                    if (reply[0] == query[0] and reply[1] == query[1]) break .{ query, answer };
                } else {
                    continue;
                };
                if (answer.len != 0) continue;

                // Only accept positive or negative responses; retry immediately on
                // server failure, and ignore all other codes such as refusal.
                switch (reply[3] & 15) {
                    0, 3 => {
                        answer.* = reply;
                        answer_buffer_i += reply.len;
                        answers_remaining -= 1;
                        if (answer_buffer.len - answer_buffer_i == 0) break :send;
                        if (answers_remaining == 0) break :send;
                    },
                    2 => {
                        socket.sendTimeout(t_io, ns, query, timeout) catch |err| switch (err) {
                            error.Canceled => |e| return e,
                            error.Timeout => continue :send,
                            else => {},
                        };
                        continue;
                    },
                    else => continue,
                }
            }
            if (recv_err) |err| switch (err) {
                error.Canceled => |e| return e,
                error.Timeout => continue :send,
                else => continue,
            };
        }
    } else {
        return error.NameServerFailure;
    }

    var addresses_len: usize = 0;
    var canonical_name: ?HostName = null;

    for (answers) |answer| {
        var it = HostName.DnsResponse.init(answer) catch {
            // Here we could potentially add diagnostics to the results queue.
            continue;
        };
        while (it.next() catch {
            // Here we could potentially add diagnostics to the results queue.
            continue;
        }) |record| switch (record.rr) {
            .A => {
                const data = record.packet[record.data_off..][0..record.data_len];
                if (data.len != 4) return error.InvalidDnsARecord;
                try resolved.putOne(t_io, .{ .address = .{ .ip4 = .{
                    .bytes = data[0..4].*,
                    .port = options.port,
                } } });
                addresses_len += 1;
            },
            .AAAA => {
                const data = record.packet[record.data_off..][0..record.data_len];
                if (data.len != 16) return error.InvalidDnsAAAARecord;
                try resolved.putOne(t_io, .{ .address = .{ .ip6 = .{
                    .bytes = data[0..16].*,
                    .port = options.port,
                } } });
                addresses_len += 1;
            },
            .CNAME => {
                if (options.canonical_name_buffer) |buf| {
                    _, canonical_name = HostName.expand(
                        record.packet,
                        record.data_off,
                        buf,
                    ) catch return error.InvalidDnsCnameRecord;
                }
            },
            _ => continue,
        };
    }

    if (options.canonical_name_buffer != null) {
        try resolved.putOne(t_io, .{
            .canonical_name = canonical_name orelse .{ .bytes = lookup_canon_name },
        });
    }
    if (addresses_len == 0) return error.NoAddressReturned;
}

pub fn lookupHosts(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) !void {
    const path_w = if (is_windows) path_w: {
        var path_w_buf: [windows.PATH_MAX_WIDE:0]u16 = undefined;
        const system_dir = windows.getSystemDirectoryWtf16Le();
        const suffix = [_]u16{
            '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'e', 't', 'c', '\\', 'h', 'o', 's', 't', 's',
        };
        @memcpy(path_w_buf[0..system_dir.len], system_dir);
        @memcpy(path_w_buf[system_dir.len..][0..suffix.len], &suffix);
        path_w_buf[system_dir.len + suffix.len] = 0;
        break :path_w windows_impl.wToPrefixedFileW(null, &path_w_buf, .{}) catch |err| switch (err) {
            error.FileNotFound,
            error.AccessDenied,
            => return error.UnknownHostName,

            error.Canceled => |e| return e,

            else => {
                // Here we could add more detailed diagnostics to the results queue.
                return error.DetectingNetworkConfigurationFailed;
            },
        };
    };
    const file = (if (is_windows)
        windows_impl.dirOpenFileWtf16(null, path_w.span(), .{})
    else
        dirOpenFile(t, .cwd(), "/etc/hosts", .{})) catch |err| switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        => return error.UnknownHostName,

        error.Canceled => |e| return e,

        else => {
            // Here we could add more detailed diagnostics to the results queue.
            return error.DetectingNetworkConfigurationFailed;
        },
    };
    defer fileClose(t, &.{file});

    var line_buf: [512]u8 = undefined;
    var file_reader = file.reader(t.io(), &line_buf);
    return lookupHostsReader(t, host_name, resolved, options, &file_reader.interface) catch |err| switch (err) {
        error.ReadFailed => switch (file_reader.err.?) {
            error.Canceled => |e| return e,
            else => {
                // Here we could add more detailed diagnostics to the results queue.
                return error.DetectingNetworkConfigurationFailed;
            },
        },
        error.Canceled,
        error.Closed,
        error.UnknownHostName,
        => |e| return e,
    };
}

pub fn lookupHostsReader(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
    reader: *Io.Reader,
) error{ ReadFailed, Canceled, UnknownHostName, Closed }!void {
    const t_io = io(t);
    var addresses_len: usize = 0;
    var canonical_name: ?HostName = null;
    while (true) {
        const line = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                // Skip lines that are too long.
                _ = reader.discardDelimiterInclusive('\n') catch |er| switch (er) {
                    error.EndOfStream => break,
                    error.ReadFailed => |e| return e,
                };
                continue;
            },
            error.ReadFailed => |e| return e,
            error.EndOfStream => break,
        };
        reader.toss(@min(1, reader.bufferedLen()));
        var split_it = std.mem.splitScalar(u8, if (is_windows and std.mem.endsWith(u8, line, "\r"))
            line[0 .. line.len - 1]
        else
            line, '#');
        const no_comment_line = split_it.first();

        var line_it = std.mem.tokenizeAny(u8, no_comment_line, " \t");
        const ip_text = line_it.next() orelse continue;
        var first_name_text: ?[]const u8 = null;
        while (line_it.next()) |name_text| {
            if (std.ascii.eqlIgnoreCase(name_text, host_name.bytes)) {
                if (first_name_text == null) first_name_text = name_text;
                break;
            }
        } else continue;

        if (canonical_name == null) {
            if (options.canonical_name_buffer) |buf| {
                if (HostName.init(first_name_text.?)) |name_text| {
                    if (name_text.bytes.len <= buf.len) {
                        const canonical_name_dest = buf[0..name_text.bytes.len];
                        @memcpy(canonical_name_dest, name_text.bytes);
                        canonical_name = .{ .bytes = canonical_name_dest };
                    }
                } else |_| {}
            }
        }

        if (options.family != .ip6) {
            if (IpAddress.parseIp4(ip_text, options.port)) |addr| {
                try resolved.putOne(t_io, .{ .address = addr });
                addresses_len += 1;
            } else |_| {}
        }
        if (options.family != .ip4) {
            if (IpAddress.parseIp6(ip_text, options.port)) |addr| {
                try resolved.putOne(t_io, .{ .address = addr });
                addresses_len += 1;
            } else |_| {}
        }
    }

    if (canonical_name) |canon_name| try resolved.putOne(t_io, .{ .canonical_name = canon_name });
    if (addresses_len == 0) return error.UnknownHostName;
}

/// Writes DNS resolution query packet data to `w`; at most 280 bytes.
pub fn writeResolutionQuery(q: *[280]u8, op: u4, dname: []const u8, class: u8, ty: HostName.DnsRecord, entropy: [2]u8) usize {
    // This implementation is ported from musl libc.
    // A more idiomatic "ziggy" implementation would be welcome.
    var name = dname;
    if (std.mem.endsWith(u8, name, ".")) name.len -= 1;
    assert(name.len <= 253);
    const n = 17 + name.len + @intFromBool(name.len != 0);

    // Construct query template - ID will be filled later
    q[0..2].* = entropy;
    @memset(q[2..n], 0);
    q[2] = @as(u8, op) * 8 + 1;
    q[5] = 1;
    @memcpy(q[13..][0..name.len], name);
    var i: usize = 13;
    var j: usize = undefined;
    while (q[i] != 0) : (i = j + 1) {
        j = i;
        while (q[j] != 0 and q[j] != '.') : (j += 1) {}
        // TODO determine the circumstances for this and whether or
        // not this should be an error.
        if (j - i - 1 > 62) unreachable;
        q[i - 1] = @intCast(j - i);
    }
    q[i + 1] = @backingInt(ty);
    q[i + 3] = class;
    return n;
}

pub fn copyCanon(canonical_name_buffer: ?*[HostName.max_len]u8, name: []const u8) ?HostName {
    const buf = canonical_name_buffer orelse return null;
    const dest = buf[0..name.len];
    @memcpy(dest, name);
    return .{ .bytes = dest };
}
