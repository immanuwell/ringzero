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

const default_pindir = "/sys/fs/bpf/ringzero";
const default_obj = "bpf/xdp_lb.o";
const prog_name = "xdp_lb_prog";

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

// ---------------------------------------------------------------------------
// small parsing helpers
// ---------------------------------------------------------------------------

fn parseIp(s: []const u8) !u32 {
    var buf: [64]u8 = undefined;
    const z = try std.fmt.bufPrintZ(&buf, "{s}", .{s});
    var result: u32 = 0;
    const ret = c.inet_pton(c.AF_INET, z.ptr, @ptrCast(&result));
    if (ret != 1) return error.InvalidIp;
    return result;
}

fn ipToStr(buf: []u8, addr_be: u32) ![]u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        (addr_be >> 24) & 0xff,
        (addr_be >> 16) & 0xff,
        (addr_be >> 8) & 0xff,
        addr_be & 0xff,
    });
}

fn parseMac(s: []const u8) ![6]u8 {
    var out: [6]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, ':');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 6) return error.InvalidMac;
        out[i] = try std.fmt.parseInt(u8, part, 16);
    }
    if (i != 6) return error.InvalidMac;
    return out;
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
    if (c.mkdir(z.ptr, 0o755) != 0 and c.__errno_location().* != c.EEXIST)
        fatal("mkdir({s}) failed: errno {d}", .{ pindir, c.__errno_location().* });
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
        var info: c.struct_vip_info = undefined;
        if (c.bpf_map_lookup_elem(fd, &key, &info) == 0) {
            if (info.vip_id < c.MAX_VIPS) used[info.vip_id] = true;
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
    var ids = std.array_list.Managed(u32).init(allocator);
    defer ids.deinit();

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
        try ids.append(key);
    }

    const table = try allocator.alloc(i64, c.MAGLEV_TABLE_SIZE);
    defer allocator.free(table);
    try maglev.build(allocator, ids.items, c.MAGLEV_TABLE_SIZE, table);

    var slot: u32 = 0;
    while (slot < c.MAGLEV_TABLE_SIZE) : (slot += 1) {
        const mkey = vip_id * c.MAGLEV_TABLE_SIZE + slot;
        const val: u32 = if (table[slot] < 0) c.BACKEND_ID_NONE else @intCast(table[slot]);
        if (c.bpf_map_update_elem(maps.maglev, &mkey, &val, c.BPF_ANY) != 0)
            fatal("failed writing maglev_map[{d}]", .{mkey});
    }
    std.debug.print("rebuilt maglev table for vip_id={d}: {d} healthy backend(s)\n", .{ vip_id, ids.items.len });
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

    mkdirIfMissing(pindir);
    var pin_buf: [512]u8 = undefined;
    const pin_z = try std.fmt.bufPrintZ(&pin_buf, "{s}", .{pindir});
    const pin_ret = c.bpf_object__pin_maps(obj, pin_z.ptr);
    if (pin_ret != 0) fatal("bpf_object__pin_maps({s}) failed: {d} (maps already pinned from a previous attach? try `detach --purge` first)", .{ pindir, pin_ret });

    const ifindex = try ifNameToIndex(iface);

    const drv_flags: u32 = c.XDP_FLAGS_UPDATE_IF_NOEXIST | c.XDP_FLAGS_DRV_MODE;
    const skb_flags: u32 = c.XDP_FLAGS_UPDATE_IF_NOEXIST | c.XDP_FLAGS_SKB_MODE;

    var used_mode: []const u8 = "native (driver, XDP_FLAGS_DRV_MODE)";
    var ret: c_int = -1;
    if (std.mem.eql(u8, mode, "native") or std.mem.eql(u8, mode, "auto")) {
        ret = c.bpf_xdp_attach(@intCast(ifindex), prog_fd, drv_flags, null);
    }
    if (ret != 0 and (std.mem.eql(u8, mode, "generic") or std.mem.eql(u8, mode, "auto"))) {
        ret = c.bpf_xdp_attach(@intCast(ifindex), prog_fd, skb_flags, null);
        used_mode = "generic (SKB, XDP_FLAGS_SKB_MODE)";
    }
    if (ret != 0) fatal("bpf_xdp_attach on {s} (ifindex {d}) failed: {d}. Native XDP needs NIC driver support; try --mode generic.", .{ iface, ifindex, ret });

    std.debug.print(
        \\attached xdp_lb_prog to {s} (ifindex {d}) in {s} mode
        \\maps pinned under {s}
        \\
    , .{ iface, ifindex, used_mode, pindir });
}

fn cmdDetach(flags: Flags) !void {
    const iface = flags.getReq("--iface");
    const pindir = flags.getDefault("--pindir", default_pindir);
    const ifindex = try ifNameToIndex(iface);
    const ret = c.bpf_xdp_detach(@intCast(ifindex), 0, null);
    if (ret != 0) fatal("bpf_xdp_detach failed: {d}", .{ret});
    std.debug.print("detached xdp program from {s}\n", .{iface});

    if (flags.has("--purge")) {
        purgePinDir(pindir);
        std.debug.print("removed pinned maps under {s}\n", .{pindir});
    }
}

fn printUsage() void {
    std.debug.print(
        \\ringzero -- control plane for the XDP load balancer
        \\
        \\usage:
        \\  ringzero attach --iface IFACE [--obj bpf/xdp_lb.o] [--mode auto|native|generic] [--pindir DIR]
        \\  ringzero detach --iface IFACE [--purge] [--pindir DIR]
        \\
    , .{});
}

pub fn main(init: std.process.Init.Minimal) !void {
    const allocator = std.heap.smp_allocator;

    var arg_it = init.args.iterate();
    var argv_list = std.array_list.Managed([]const u8).init(allocator);
    defer argv_list.deinit();
    while (arg_it.next()) |a| try argv_list.append(a);
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
    } else if (std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        printUsage();
    } else {
        std.debug.print("unknown command: {s}\n\n", .{cmd});
        printUsage();
        std.process.exit(1);
    }
}
