//! ringzero — the userspace control plane for the XDP load balancer.
//!
//! The data plane (bpf/xdp_lb.c) never talks to this program directly once
//! attached: it only reads BPF maps. This binary's whole job is to load the
//! BPF object, attach it to an interface, and then maintain those maps —
//! which VIPs exist, which backends serve them, which backends are healthy,
//! and the Maglev consistent-hash table that ties flows to backends. Every
//! subcommand below is a short-lived process except `stats --watch` and
//! `healthcheck`, which loop; state lives entirely in the pinned BPF maps
//! under --pindir, not in this process, so commands can be run independently
//! at any time (e.g. from a shell script orchestrating a demo).
const std = @import("std");
const c = @import("c.zig").c;
const maglev = @import("maglev.zig");

comptime {
    // maglev.build keeps per-backend state in fixed-size stack arrays, and its
    // own bounds assert is compiled out in ReleaseFast. Fail the build instead.
    std.debug.assert(c.MAX_BACKENDS <= maglev.max_backends);
}

const default_pindir = "/sys/fs/bpf/ringzero";
const default_obj = "bpf/xdp_lb.o";
const prog_name = "xdp_lb_prog";

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

/// All set once in main. The writer has to be one long-lived instance:
/// File.Writer tracks a file position, so a fresh one per line rewrites byte 0
/// of a redirect and only the last line survives.
var io: std.Io = undefined;
var stdout_buf: [4096]u8 = undefined;
var stdout_file: std.Io.File.Writer = undefined;
var out: *std.Io.Writer = undefined;

/// Results go to stdout so they can be redirected; std.debug.print (stderr)
/// stays for errors and diagnostics.
fn info(comptime fmt: []const u8, args: anytype) void {
    out.print(fmt ++ "\n", args) catch return;
    // Per line, because fatal() exits without unwinding.
    out.flush() catch return;
}

// ---------------------------------------------------------------------------
// small parsing helpers
// ---------------------------------------------------------------------------

/// Returns the address in network byte order, the form the BPF maps store.
fn parseIp(s: []const u8) !u32 {
    const a = std.Io.net.Ip4Address.parse(s, 0) catch return error.InvalidIp;
    return @bitCast(a.bytes);
}

/// The u32 holds the octets in wire order, so its bytes are the dotted quad
/// on any host.
fn ipToStr(buf: []u8, addr_be: u32) ![]u8 {
    const o: [4]u8 = @bitCast(addr_be);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ o[0], o[1], o[2], o[3] });
}

fn parseMac(s: []const u8) ![6]u8 {
    var mac: [6]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, ':');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 6) return error.InvalidMac;
        mac[i] = try std.fmt.parseInt(u8, part, 16);
    }
    if (i != 6) return error.InvalidMac;
    return mac;
}

fn macToStr(buf: []u8, mac: [6]u8) ![]u8 {
    return std.fmt.bufPrint(buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    });
}

fn ifNameToIndex(name: []const u8) !u32 {
    var buf: [c.IFNAMSIZ + 1]u8 = undefined;
    const z = try std.fmt.bufPrintZ(&buf, "{s}", .{name});
    const idx = c.if_nametoindex(z.ptr);
    if (idx == 0) return error.NoSuchInterface;
    return idx;
}

fn parseProto(s: []const u8) !u8 {
    if (std.mem.eql(u8, s, "tcp")) return c.IPPROTO_TCP_;
    if (std.mem.eql(u8, s, "udp")) return c.IPPROTO_UDP_;
    return error.InvalidProto;
}

fn protoName(p: u8) []const u8 {
    return if (p == c.IPPROTO_TCP_) "tcp" else if (p == c.IPPROTO_UDP_) "udp" else "?";
}

/// Parses "ip:port/proto", e.g. "10.0.0.1:8080/udp".
const VipSpec = struct { addr: u32, port: u16, proto: u8 };
fn parseVipSpec(s: []const u8) !VipSpec {
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidVipSpec;
    const proto = try parseProto(s[slash + 1 ..]);
    const colon = std.mem.indexOfScalar(u8, s[0..slash], ':') orelse return error.InvalidVipSpec;
    const addr = try parseIp(s[0..colon]);
    const port = try std.fmt.parseInt(u16, s[colon + 1 .. slash], 10);
    return .{ .addr = addr, .port = std.mem.nativeToBig(u16, port), .proto = proto };
}

test "parseIp round-trips through ipToStr" {
    var buf: [16]u8 = undefined;
    for ([_][]const u8{ "0.0.0.0", "10.20.0.2", "192.168.1.255", "255.255.255.255" }) |s| {
        try std.testing.expectEqualStrings(s, try ipToStr(&buf, try parseIp(s)));
    }
    try std.testing.expectError(error.InvalidIp, parseIp("10.0.0"));
    try std.testing.expectError(error.InvalidIp, parseIp("256.0.0.1"));
    try std.testing.expectError(error.InvalidIp, parseIp(""));
}

test "parseIp yields network byte order" {
    // 1.2.3.4 on the wire is the bytes 01 02 03 04, whichever way the host
    // orders integers.
    const octets: [4]u8 = @bitCast(try parseIp("1.2.3.4"));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, &octets);
}

test "parseMac" {
    try std.testing.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 }, try parseMac("aa:bb:cc:dd:ee:01"));
    try std.testing.expectError(error.InvalidMac, parseMac("aa:bb:cc:dd:ee"));
    try std.testing.expectError(error.InvalidMac, parseMac("aa:bb:cc:dd:ee:01:02"));
}

test "parseVipSpec" {
    const v = try parseVipSpec("10.0.0.1:8080/udp");
    try std.testing.expectEqual(try parseIp("10.0.0.1"), v.addr);
    try std.testing.expectEqual(@as(u16, 8080), std.mem.bigToNative(u16, v.port));
    try std.testing.expectEqual(@as(u8, c.IPPROTO_UDP_), v.proto);

    try std.testing.expectError(error.InvalidVipSpec, parseVipSpec("10.0.0.1:8080"));
    try std.testing.expectError(error.InvalidVipSpec, parseVipSpec("10.0.0.1/udp"));
    try std.testing.expectError(error.InvalidProto, parseVipSpec("10.0.0.1:80/sctp"));
}

test "maglev sentinel matches the BPF one" {
    try std.testing.expectEqual(@as(u32, c.BACKEND_ID_NONE), maglev.none);
    try std.testing.expect(c.MAX_BACKENDS <= maglev.max_backends);
}

// ---------------------------------------------------------------------------
// tiny arg parser: flags are always `--name value`, order doesn't matter.
// ---------------------------------------------------------------------------

const Flags = struct {
    args: []const []const u8,

    fn get(self: Flags, name: []const u8) ?[]const u8 {
        var i: usize = 0;
        while (i < self.args.len) : (i += 1) {
            if (std.mem.eql(u8, self.args[i], name)) {
                if (i + 1 >= self.args.len) fatal("flag {s} needs a value", .{name});
                return self.args[i + 1];
            }
        }
        return null;
    }

    fn getReq(self: Flags, name: []const u8) []const u8 {
        return self.get(name) orelse fatal("missing required flag {s}", .{name});
    }

    fn getDefault(self: Flags, name: []const u8, default: []const u8) []const u8 {
        return self.get(name) orelse default;
    }

    fn has(self: Flags, name: []const u8) bool {
        for (self.args) |a| {
            if (std.mem.eql(u8, a, name)) return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// pinned-map access
// ---------------------------------------------------------------------------

fn mkdirIfMissing(pindir: []const u8) void {
    var buf: [512]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{pindir}) catch fatal("pindir path too long", .{});
    if (c.mkdir(z.ptr, 0o755) != 0 and std.c._errno().* != c.EEXIST)
        fatal("mkdir({s}) failed: errno {d}", .{ pindir, std.c._errno().* });
}

fn purgePinDir(pindir: []const u8) void {
    const names = [_][]const u8{ "vip_map", "backend_map", "maglev_map", "stats_map" };
    for (names) |name| {
        var buf: [512]u8 = undefined;
        const z = std.fmt.bufPrintZ(&buf, "{s}/{s}", .{ pindir, name }) catch continue;
        _ = c.unlink(z.ptr);
    }
    var dbuf: [512]u8 = undefined;
    const dz = std.fmt.bufPrintZ(&dbuf, "{s}", .{pindir}) catch return;
    _ = c.rmdir(dz.ptr);
}

/// Serializes the mutating commands -- they're all read-modify-write over the
/// maps, and `healthcheck` runs one in a loop. Not under --pindir: bpffs
/// rejects O_CREAT of a regular file.
const lock_path = "/run/ringzero.lock";
const lock_wait_ms = 2000;

/// Null if another command held the lock past lock_wait_ms.
fn tryLockControlPlane() ?c_int {
    const fd = c.open(lock_path, c.O_RDWR | c.O_CREAT | c.O_CLOEXEC, @as(c_uint, 0o644));
    // No lock file at all is how things worked before there was a lock, so
    // that still runs, just unserialized. Contention is different: another
    // command is mid-update, and going ahead would interleave with it.
    if (fd < 0) {
        std.debug.print("warning: no {s}, running unserialized\n", .{lock_path});
        return -1;
    }
    // Bounded so a stuck holder cannot turn a command that never blocked into
    // a hang -- but give up rather than mutate unserialized, since every
    // update is read-modify-write and update_batch is not atomic either.
    var waited: u32 = 0;
    while (c.flock(fd, c.LOCK_EX | c.LOCK_NB) != 0) {
        const err = std.c._errno().*;
        if (err != c.EWOULDBLOCK and err != c.EINTR)
            fatal("flock({s}) failed: errno {d}", .{ lock_path, err });
        if (waited >= lock_wait_ms) {
            _ = c.close(fd);
            return null;
        }
        _ = c.usleep(20_000);
        waited += 20;
    }
    return fd;
}

fn lockControlPlane() c_int {
    return tryLockControlPlane() orelse
        fatal("{s} held for over {d}ms -- is another ringzero running?", .{ lock_path, lock_wait_ms });
}

fn unlockControlPlane(fd: c_int) void {
    if (fd < 0) return;
    _ = c.flock(fd, c.LOCK_UN);
    _ = c.close(fd);
}

fn pinnedFd(pindir: []const u8, name: []const u8) c_int {
    var buf: [512]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buf, "{s}/{s}", .{ pindir, name }) catch fatal("path too long", .{});
    const fd = c.bpf_obj_get(path.ptr);
    if (fd < 0) fatal("could not open pinned map {s} (did you run `attach` first?)", .{path});
    return fd;
}

const Maps = struct {
    vip: c_int,
    backend: c_int,
    maglev: c_int,
    stats: c_int,

    fn open(pindir: []const u8) Maps {
        return .{
            .vip = pinnedFd(pindir, "vip_map"),
            .backend = pinnedFd(pindir, "backend_map"),
            .maglev = pinnedFd(pindir, "maglev_map"),
            .stats = pinnedFd(pindir, "stats_map"),
        };
    }

    fn close(self: Maps) void {
        _ = c.close(self.vip);
        _ = c.close(self.backend);
        _ = c.close(self.maglev);
        _ = c.close(self.stats);
    }
};

/// Finds the first backend id in [0, MAX_BACKENDS) with no entry in backend_map.
fn nextFreeBackendId(fd: c_int) !u32 {
    var id: u32 = 0;
    while (id < c.MAX_BACKENDS) : (id += 1) {
        var tmp: c.struct_backend = undefined;
        const ret = c.bpf_map_lookup_elem(fd, &id, &tmp);
        if (ret != 0) return id; // ENOENT => free
    }
    return error.NoFreeBackendSlots;
}

/// Finds the first vip_id in [0, MAX_VIPS) not currently used by any entry
/// in vip_map (scanned via full iteration since the map key is a vip_key,
/// not the id).
fn nextFreeVipId(fd: c_int) !u32 {
    var used = [_]bool{false} ** c.MAX_VIPS;
    var key: c.struct_vip_key = undefined;
    var next_key: c.struct_vip_key = undefined;
    var have_key = false;
    while (true) {
        const key_ptr: ?*c.struct_vip_key = if (have_key) &key else null;
        if (c.bpf_map_get_next_key(fd, key_ptr, &next_key) != 0) break;
        key = next_key;
        have_key = true;
        var vinfo: c.struct_vip_info = undefined;
        if (c.bpf_map_lookup_elem(fd, &key, &vinfo) == 0) {
            if (vinfo.vip_id < c.MAX_VIPS) used[vinfo.vip_id] = true;
        }
    }
    for (used, 0..) |u, i| {
        if (!u) return @intCast(i);
    }
    return error.NoFreeVipSlots;
}

/// Recomputes the Maglev table for `vip_id` from every healthy backend
/// currently assigned to it in backend_map, and pushes the full table (all
/// MAGLEV_TABLE_SIZE slots, including BACKEND_ID_NONE for unfilled ones) into
/// maglev_map. This is the only place that writes maglev_map.
fn rebuildMaglev(allocator: std.mem.Allocator, maps: Maps, vip_id: u32) !void {
    var ids = std.ArrayList(u32).empty;
    defer ids.deinit(allocator);

    var key: u32 = undefined;
    var next_key: u32 = undefined;
    var have_key = false;
    while (true) {
        const key_ptr: ?*u32 = if (have_key) &key else null;
        if (c.bpf_map_get_next_key(maps.backend, key_ptr, &next_key) != 0) break;
        key = next_key;
        have_key = true;
        var be: c.struct_backend = undefined;
        if (c.bpf_map_lookup_elem(maps.backend, &key, &be) != 0) continue;
        if (be.vip_id != vip_id) continue;
        if (be.flags & c.BACKEND_FLAG_HEALTHY == 0) continue;
        try ids.append(allocator, key);
    }

    if (ids.items.len > maglev.max_backends)
        fatal("vip_id {d} has {d} backends, more than maglev handles", .{ vip_id, ids.items.len });

    // get_next_key walks the hash map in bucket order. Maglev fills slots in
    // input order, so sort to keep the table a function of the backend set.
    std.mem.sort(u32, ids.items, {}, std.sort.asc(u32));

    const table = try allocator.alloc(u32, c.MAGLEV_TABLE_SIZE);
    defer allocator.free(table);
    maglev.build(ids.items, table);

    // One batch syscall instead of MAGLEV_TABLE_SIZE of them, which also
    // narrows the window where the data plane sees a half-updated table.
    const keys = try allocator.alloc(u32, c.MAGLEV_TABLE_SIZE);
    defer allocator.free(keys);
    for (keys, 0..) |*k, i| k.* = vip_id * c.MAGLEV_TABLE_SIZE + @as(u32, @intCast(i));

    var count: u32 = c.MAGLEV_TABLE_SIZE;
    if (c.bpf_map_update_batch(maps.maglev, keys.ptr, table.ptr, &count, null) != 0 or count != c.MAGLEV_TABLE_SIZE)
        fatal("maglev_map batch update wrote {d}/{d} slots for vip_id {d}; the table is now a mix of two", .{ count, c.MAGLEV_TABLE_SIZE, vip_id });
    info("rebuilt maglev table for vip_id={d}: {d} healthy backend(s)", .{ vip_id, ids.items.len });
}

// ---------------------------------------------------------------------------
// subcommands (more to come)
// ---------------------------------------------------------------------------

fn cmdAttach(flags: Flags) !void {
    const iface = flags.getReq("--iface");
    const obj_path = flags.getDefault("--obj", default_obj);
    const pindir = flags.getDefault("--pindir", default_pindir);
    const mode = flags.getDefault("--mode", "auto");

    var obj_buf: [512]u8 = undefined;
    const obj_z = try std.fmt.bufPrintZ(&obj_buf, "{s}", .{obj_path});
    const obj = c.bpf_object__open(obj_z.ptr) orelse fatal("bpf_object__open({s}) failed", .{obj_path});

    if (c.bpf_object__load(obj) != 0) fatal("bpf_object__load failed (check dmesg / verifier log)", .{});

    var prog_buf: [64]u8 = undefined;
    const prog_z = try std.fmt.bufPrintZ(&prog_buf, "{s}", .{prog_name});
    const prog = c.bpf_object__find_program_by_name(obj, prog_z.ptr) orelse fatal("program {s} not found in object", .{prog_name});
    const prog_fd = c.bpf_program__fd(prog);
    if (prog_fd < 0) fatal("bpf_program__fd failed", .{});

    const ifindex = ifNameToIndex(iface) catch fatal("no such interface: {s}", .{iface});

    const drv_flags: u32 = c.XDP_FLAGS_UPDATE_IF_NOEXIST | c.XDP_FLAGS_DRV_MODE;
    const skb_flags: u32 = c.XDP_FLAGS_UPDATE_IF_NOEXIST | c.XDP_FLAGS_SKB_MODE;

    // Attach before pinning, so a failed attach doesn't leave pins behind for
    // the next run to trip over.
    var used_mode: []const u8 = "native (driver, XDP_FLAGS_DRV_MODE)";
    var used_flags: u32 = drv_flags;
    var ret: c_int = -1;
    if (std.mem.eql(u8, mode, "native") or std.mem.eql(u8, mode, "auto")) {
        ret = c.bpf_xdp_attach(@intCast(ifindex), prog_fd, drv_flags, null);
    }
    if (ret != 0 and (std.mem.eql(u8, mode, "generic") or std.mem.eql(u8, mode, "auto"))) {
        ret = c.bpf_xdp_attach(@intCast(ifindex), prog_fd, skb_flags, null);
        used_mode = "generic (SKB, XDP_FLAGS_SKB_MODE)";
        used_flags = skb_flags;
    }
    if (ret != 0) fatal("bpf_xdp_attach on {s} (ifindex {d}) failed: {d}. Native XDP needs NIC driver support; try --mode generic.", .{ iface, ifindex, ret });

    mkdirIfMissing(pindir);
    var pin_buf: [512]u8 = undefined;
    const pin_z = try std.fmt.bufPrintZ(&pin_buf, "{s}", .{pindir});
    const pin_ret = c.bpf_object__pin_maps(obj, pin_z.ptr);
    if (pin_ret != 0) {
        // Unpinned maps mean no later command can find the program, so back
        // the attach out rather than leave a data plane nobody can configure.
        _ = c.bpf_xdp_detach(@intCast(ifindex), used_flags, null);
        fatal("bpf_object__pin_maps({s}) failed: {d} (maps already pinned from a previous attach? try `detach --purge` first)", .{ pindir, pin_ret });
    }

    info(
        \\attached xdp_lb_prog to {s} (ifindex {d}) in {s} mode
        \\maps pinned under {s}
    , .{ iface, ifindex, used_mode, pindir });
}

fn cmdDetach(flags: Flags) !void {
    const iface = flags.getReq("--iface");
    const pindir = flags.getDefault("--pindir", default_pindir);
    const ifindex = ifNameToIndex(iface) catch fatal("no such interface: {s}", .{iface});

    // bpf_xdp_detach(flags=0) doesn't reliably auto-detect which mode is
    // currently attached on every kernel/libbpf combination -- query first
    // and detach with the matching flag so this works whether `attach` fell
    // back to generic mode or not.
    var prog_id: u32 = 0;
    var mode_flags: u32 = 0;
    if (c.bpf_xdp_query_id(@intCast(ifindex), c.XDP_FLAGS_DRV_MODE, &prog_id) == 0 and prog_id != 0) {
        mode_flags = c.XDP_FLAGS_DRV_MODE;
    } else if (c.bpf_xdp_query_id(@intCast(ifindex), c.XDP_FLAGS_SKB_MODE, &prog_id) == 0 and prog_id != 0) {
        mode_flags = c.XDP_FLAGS_SKB_MODE;
    }

    const ret = c.bpf_xdp_detach(@intCast(ifindex), mode_flags, null);
    if (ret != 0) fatal("bpf_xdp_detach failed: {d}", .{ret});
    info("detached xdp program from {s}", .{iface});

    if (flags.has("--purge")) {
        purgePinDir(pindir);
        info("removed pinned maps under {s}", .{pindir});
    }
}

fn cmdVipAdd(allocator: std.mem.Allocator, flags: Flags) !void {
    const pindir = flags.getDefault("--pindir", default_pindir);
    const vip_str = flags.getReq("--vip");
    const addr = parseIp(vip_str) catch fatal("invalid --vip address: {s}", .{vip_str});
    const port_str = flags.getReq("--port");
    const port_num = std.fmt.parseInt(u16, port_str, 10) catch fatal("invalid --port: {s} (expected 0-65535, 0 for any port)", .{port_str});
    const proto_str = flags.getReq("--proto");
    const proto = parseProto(proto_str) catch fatal("invalid --proto: {s} (expected tcp or udp)", .{proto_str});

    const lock = lockControlPlane();
    defer unlockControlPlane(lock);

    const maps = Maps.open(pindir);
    defer maps.close();

    const vip_id = try nextFreeVipId(maps.vip);
    var key = std.mem.zeroes(c.struct_vip_key);
    key.vip_addr = addr;
    key.vip_port = std.mem.nativeToBig(u16, port_num);
    key.proto = proto;

    var vinfo = std.mem.zeroes(c.struct_vip_info);
    vinfo.vip_id = vip_id;
    vinfo.backend_count = 0;

    // Blank the slice before the VIP is reachable: an ARRAY map reads back as
    // zeros, and 0 is a valid backend id. Publishing the row first leaves a
    // window where traffic matches the VIP and reads whatever the previous
    // holder of this id left behind.
    try rebuildMaglev(allocator, maps, vip_id);

    if (c.bpf_map_update_elem(maps.vip, &key, &vinfo, c.BPF_NOEXIST) != 0)
        fatal("vip already exists (or vip_map update failed)", .{});

    info("added vip {s}:{d}/{s} -> vip_id {d}", .{ vip_str, port_num, protoName(proto), vip_id });
}

fn cmdBackendAdd(allocator: std.mem.Allocator, flags: Flags) !void {
    const pindir = flags.getDefault("--pindir", default_pindir);
    const spec_str = flags.getReq("--vip");
    const vip_spec = parseVipSpec(spec_str) catch fatal("invalid --vip: {s} (expected IP:PORT/tcp|udp)", .{spec_str});
    const addr_str = flags.getReq("--addr");
    const addr = parseIp(addr_str) catch fatal("invalid --addr: {s}", .{addr_str});
    const mac_str = flags.getReq("--mac");
    const mac = parseMac(mac_str) catch fatal("invalid --mac: {s}", .{mac_str});
    const rmac_str = flags.getReq("--router-mac");
    const router_mac = parseMac(rmac_str) catch fatal("invalid --router-mac: {s}", .{rmac_str});
    const egress_iface = flags.getReq("--iface");
    const ifindex = ifNameToIndex(egress_iface) catch fatal("no such interface: {s}", .{egress_iface});

    const lock = lockControlPlane();
    defer unlockControlPlane(lock);

    const maps = Maps.open(pindir);
    defer maps.close();

    var vkey = std.mem.zeroes(c.struct_vip_key);
    vkey.vip_addr = vip_spec.addr;
    vkey.vip_port = vip_spec.port;
    vkey.proto = vip_spec.proto;
    var vinfo: c.struct_vip_info = undefined;
    if (c.bpf_map_lookup_elem(maps.vip, &vkey, &vinfo) != 0)
        fatal("vip not found -- run `vip-add` first", .{});

    const backend_id = try nextFreeBackendId(maps.backend);
    var be = std.mem.zeroes(c.struct_backend);
    be.addr = addr;
    be.mac = mac;
    be.router_mac = router_mac;
    be.ifindex_egress = ifindex;
    be.vip_id = vinfo.vip_id;
    be.port = vip_spec.port;
    be.proto = vip_spec.proto;
    be.flags = c.BACKEND_FLAG_HEALTHY;

    // NOEXIST, not ANY: nextFreeBackendId only observed the slot was free, it
    // didn't reserve it.
    if (c.bpf_map_update_elem(maps.backend, &backend_id, &be, c.BPF_NOEXIST) != 0)
        fatal("backend_map update failed: id {d} was taken concurrently", .{backend_id});

    vinfo.backend_count += 1;
    if (c.bpf_map_update_elem(maps.vip, &vkey, &vinfo, c.BPF_EXIST) != 0)
        fatal("vip_map update failed while bumping backend_count", .{});

    info("added backend_id {d}: {s} (mac {s}) via {s} for vip_id {d}", .{
        backend_id, addr_str, mac_str, egress_iface, vinfo.vip_id,
    });

    try rebuildMaglev(allocator, maps, vinfo.vip_id);
}

fn cmdBackendSet(allocator: std.mem.Allocator, flags: Flags) !void {
    const pindir = flags.getDefault("--pindir", default_pindir);
    const id_str = flags.getReq("--id");
    const id = std.fmt.parseInt(u32, id_str, 10) catch fatal("invalid --id: {s}", .{id_str});
    const up = flags.has("--up");
    const down = flags.has("--down");
    if (up == down) fatal("specify exactly one of --up / --down", .{});

    const lock = lockControlPlane();
    defer unlockControlPlane(lock);

    const maps = Maps.open(pindir);
    defer maps.close();

    var be: c.struct_backend = undefined;
    if (c.bpf_map_lookup_elem(maps.backend, &id, &be) != 0) fatal("no such backend id {d}", .{id});

    if (up) be.flags |= c.BACKEND_FLAG_HEALTHY else be.flags &= ~@as(u8, c.BACKEND_FLAG_HEALTHY);
    if (c.bpf_map_update_elem(maps.backend, &id, &be, c.BPF_EXIST) != 0) fatal("update failed", .{});

    info("backend {d} marked {s}", .{ id, if (up) "UP" else "DOWN" });
    try rebuildMaglev(allocator, maps, be.vip_id);
}

fn cmdList(flags: Flags) !void {
    const pindir = flags.getDefault("--pindir", default_pindir);
    const maps = Maps.open(pindir);
    defer maps.close();

    info("VIPs:", .{});
    var vkey: c.struct_vip_key = undefined;
    var vnext: c.struct_vip_key = undefined;
    var have_vkey = false;
    while (true) {
        const key_ptr: ?*c.struct_vip_key = if (have_vkey) &vkey else null;
        if (c.bpf_map_get_next_key(maps.vip, key_ptr, &vnext) != 0) break;
        vkey = vnext;
        have_vkey = true;
        var vinfo: c.struct_vip_info = undefined;
        if (c.bpf_map_lookup_elem(maps.vip, &vkey, &vinfo) != 0) continue;
        var ipbuf: [16]u8 = undefined;
        const ipstr = try ipToStr(&ipbuf, vkey.vip_addr);
        info("  vip_id={d}  {s}:{d}/{s}  backends={d}", .{
            vinfo.vip_id, ipstr, std.mem.bigToNative(u16, vkey.vip_port), protoName(vkey.proto), vinfo.backend_count,
        });
    }

    info("Backends:", .{});
    var bkey: u32 = undefined;
    var bnext: u32 = undefined;
    var have_bkey = false;
    while (true) {
        const key_ptr: ?*u32 = if (have_bkey) &bkey else null;
        if (c.bpf_map_get_next_key(maps.backend, key_ptr, &bnext) != 0) break;
        bkey = bnext;
        have_bkey = true;
        var be: c.struct_backend = undefined;
        if (c.bpf_map_lookup_elem(maps.backend, &bkey, &be) != 0) continue;
        var ipbuf: [16]u8 = undefined;
        const ipstr = try ipToStr(&ipbuf, be.addr);
        var macbuf: [18]u8 = undefined;
        const macstr = try macToStr(&macbuf, be.mac);
        const state = if (be.flags & c.BACKEND_FLAG_HEALTHY != 0) "UP" else "DOWN";
        info("  id={d}  {s}:{d}/{s}  mac={s}  egress_ifindex={d}  vip_id={d}  {s}", .{
            bkey, ipstr, std.mem.bigToNative(u16, be.port), protoName(be.proto), macstr, be.ifindex_egress, be.vip_id, state,
        });
    }
}

fn readStatsSummed(fd: c_int, idx: u32, ncpu: usize, allocator: std.mem.Allocator) !c.struct_lb_stats {
    const buf = try allocator.alloc(c.struct_lb_stats, ncpu);
    defer allocator.free(buf);
    @memset(std.mem.sliceAsBytes(buf), 0);
    if (c.bpf_map_lookup_elem(fd, &idx, buf.ptr) != 0) return std.mem.zeroes(c.struct_lb_stats);
    var total = std.mem.zeroes(c.struct_lb_stats);
    for (buf) |s| {
        total.packets += s.packets;
        total.bytes += s.bytes;
        total.dropped += s.dropped;
        total.passed += s.passed;
    }
    return total;
}

fn cmdStats(allocator: std.mem.Allocator, flags: Flags) !void {
    const pindir = flags.getDefault("--pindir", default_pindir);
    const watch = flags.has("--watch");
    const interval_s = std.fmt.parseFloat(f64, flags.getDefault("--interval", "1.0")) catch fatal("invalid --interval", .{});
    // Negative reaches @intFromFloat on an unsigned type; 0 spins.
    if (!(interval_s > 0) or interval_s > 3600) fatal("--interval must be between 0 and 3600 seconds", .{});

    const maps = Maps.open(pindir);
    defer maps.close();

    const ncpu: usize = @intCast(c.libbpf_num_possible_cpus());

    var prev = std.mem.zeroes(c.struct_lb_stats);
    var first = true;
    var last_tick = std.Io.Clock.awake.now(io);
    while (true) {
        const cur = try readStatsSummed(maps.stats, c.STATS_GLOBAL_IDX, ncpu, allocator);
        // Saturating: a re-attach resets the counters, and cur < prev would
        // otherwise wrap into nonsense or trap.
        const dp = if (first) 0 else cur.packets -| prev.packets;
        const db = if (first) 0 else cur.bytes -| prev.bytes;
        // Rate over the time that actually passed, not the requested interval.
        const tick = std.Io.Clock.awake.now(io);
        const elapsed_s = @as(f64, @floatFromInt(last_tick.durationTo(tick).nanoseconds)) / 1_000_000_000.0;
        last_tick = tick;
        const per_s = if (first or elapsed_s <= 0) 0 else 1.0 / elapsed_s;
        const pps = @as(f64, @floatFromInt(dp)) * per_s;
        const bps = @as(f64, @floatFromInt(db)) * per_s;
        info("packets={d:>12} bytes={d:>14} dropped={d:>10} passed={d:>10}  |  {d:>12.0} pps  {d:>10.2} Mbps", .{
            cur.packets, cur.bytes, cur.dropped, cur.passed, pps, bps * 8.0 / 1_000_000.0,
        });
        prev = cur;
        first = false;
        if (!watch) break;
        _ = c.usleep(@intFromFloat(interval_s * 1_000_000.0));
    }
}

/// TCP-only health checking: attempts a short, non-blocking connect() to
/// each backend's (addr, port). UDP backends have no reliable protocol-level
/// reachability probe without an application-specific echo, so they are
/// always treated as healthy here -- flip them manually with `backend-set`
/// if you need to simulate a failure in the demo. A real deployment would
/// plug in an app-aware check here (HTTP /healthz, a UDP echo, etc.).
fn checkTcpHealthy(addr_be: u32, port_be: u16, timeout_ms: i32) bool {
    const sock = c.socket(c.AF_INET, c.SOCK_STREAM | c.SOCK_NONBLOCK, 0);
    if (sock < 0) return false;
    defer _ = c.close(sock);

    var sa = std.mem.zeroes(c.struct_sockaddr_in);
    sa.sin_family = c.AF_INET;
    sa.sin_port = port_be;
    sa.sin_addr.s_addr = addr_be;

    const ret = c.connect(sock, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in));
    if (ret != 0 and std.c._errno().* != c.EINPROGRESS) return false;

    var pfd = [_]c.struct_pollfd{.{ .fd = sock, .events = c.POLLOUT, .revents = 0 }};
    const n = c.poll(&pfd, 1, timeout_ms);
    if (n <= 0) return false;

    var opt: c_int = 0;
    var opt_len: c.socklen_t = @sizeOf(c_int);
    if (c.getsockopt(sock, c.SOL_SOCKET, c.SO_ERROR, @ptrCast(&opt), &opt_len) != 0) return false;
    return opt == 0;
}

fn cmdHealthcheck(allocator: std.mem.Allocator, flags: Flags) !void {
    const pindir = flags.getDefault("--pindir", default_pindir);
    const interval_s = try std.fmt.parseFloat(f64, flags.getDefault("--interval", "2.0"));
    const timeout_ms = try std.fmt.parseInt(i32, flags.getDefault("--timeout-ms", "300"), 10);

    const maps = Maps.open(pindir);
    defer maps.close();

    info("healthcheck loop started (interval={d}s, tcp timeout={d}ms)", .{ interval_s, timeout_ms });

    while (true) {
        var dirty_vips = std.ArrayList(u32).empty;
        defer dirty_vips.deinit(allocator);

        var key: u32 = undefined;
        var next_key: u32 = undefined;
        var have_key = false;
        while (true) {
            const key_ptr: ?*u32 = if (have_key) &key else null;
            if (c.bpf_map_get_next_key(maps.backend, key_ptr, &next_key) != 0) break;
            key = next_key;
            have_key = true;

            var be: c.struct_backend = undefined;
            if (c.bpf_map_lookup_elem(maps.backend, &key, &be) != 0) continue;

            const was_healthy = be.flags & c.BACKEND_FLAG_HEALTHY != 0;
            const now_healthy = if (be.proto == c.IPPROTO_TCP_)
                checkTcpHealthy(be.addr, be.port, timeout_ms)
            else
                true;

            if (now_healthy != was_healthy) {
                if (now_healthy) be.flags |= c.BACKEND_FLAG_HEALTHY else be.flags &= ~@as(u8, c.BACKEND_FLAG_HEALTHY);
                _ = c.bpf_map_update_elem(maps.backend, &key, &be, c.BPF_EXIST);
                var ipbuf: [16]u8 = undefined;
                const ipstr = ipToStr(&ipbuf, be.addr) catch "?";
                info("backend {d} ({s}) transitioned to {s}", .{ key, ipstr, if (now_healthy) "UP" else "DOWN" });
                var found = false;
                for (dirty_vips.items) |v| {
                    if (v == be.vip_id) found = true;
                }
                if (!found) try dirty_vips.append(allocator, be.vip_id);
            }
        }

        for (dirty_vips.items) |vip_id| {
            try rebuildMaglev(allocator, maps, vip_id);
        }

        _ = c.usleep(@intFromFloat(interval_s * 1_000_000.0));
    }
}

fn printUsage() void {
    info(
        \\ringzero -- control plane for the XDP load balancer
        \\
        \\usage:
        \\  ringzero attach --iface IFACE [--obj bpf/xdp_lb.o] [--mode auto|native|generic] [--pindir DIR]
        \\  ringzero detach --iface IFACE [--purge] [--pindir DIR]
        \\  ringzero vip-add --vip IP --port PORT --proto tcp|udp [--pindir DIR]
        \\  ringzero backend-add --vip IP:PORT/proto --addr IP --mac MAC --router-mac MAC --iface IFACE [--pindir DIR]
        \\  ringzero backend-set --id ID (--up|--down) [--pindir DIR]
        \\  ringzero list [--pindir DIR]
        \\  ringzero stats [--watch] [--interval SEC] [--pindir DIR]
        \\  ringzero healthcheck [--interval SEC] [--timeout-ms MS] [--pindir DIR]
    , .{});
}

pub fn main(init: std.process.Init) !void {
    io = init.io;
    stdout_file = std.Io.File.stdout().writer(io, &stdout_buf);
    out = &stdout_file.interface;
    // One-shot commands never need to free. The loops in healthcheck and
    // stats --watch free in LIFO order, which is what an arena reclaims.
    const allocator = init.arena.allocator();

    var arg_it = init.minimal.args.iterate();
    var argv_list: std.ArrayList([]const u8) = .empty;
    while (arg_it.next()) |a| try argv_list.append(allocator, a);
    const argv = argv_list.items;

    if (argv.len < 2) {
        printUsage();
        std.process.exit(1);
    }

    const cmd = argv[1];
    const flags = Flags{ .args = argv[2..] };

    if (std.mem.eql(u8, cmd, "attach")) {
        try cmdAttach(flags);
    } else if (std.mem.eql(u8, cmd, "detach")) {
        try cmdDetach(flags);
    } else if (std.mem.eql(u8, cmd, "vip-add")) {
        try cmdVipAdd(allocator, flags);
    } else if (std.mem.eql(u8, cmd, "backend-add")) {
        try cmdBackendAdd(allocator, flags);
    } else if (std.mem.eql(u8, cmd, "backend-set")) {
        try cmdBackendSet(allocator, flags);
    } else if (std.mem.eql(u8, cmd, "list")) {
        try cmdList(flags);
    } else if (std.mem.eql(u8, cmd, "stats")) {
        try cmdStats(allocator, flags);
    } else if (std.mem.eql(u8, cmd, "healthcheck")) {
        try cmdHealthcheck(allocator, flags);
    } else if (std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        printUsage();
    } else {
        std.debug.print("unknown command: {s}\n\n", .{cmd});
        printUsage();
        std.process.exit(1);
    }
}
