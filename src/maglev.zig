//! Maglev consistent hashing (Google, NSDI'16). Builds a lookup table of
//! `table.len` slots over a set of backend ids such that:
//!   - load is spread ~evenly across backends,
//!   - when one backend is added/removed, only ~1/N of the slots change
//!     (as opposed to naive `hash % backend_count`, where nearly every flow
//!     would get remapped to a different backend).
//!
//! This is exactly the technique Katran uses in production; the eBPF
//! program just does an O(1) array lookup into whatever table we compute
//! here and push into `maglev_map`.

const std = @import("std");

/// Mirrors BACKEND_ID_NONE in bpf/common.h.
pub const none: u32 = 0xFFFF_FFFF;

/// Bounds the per-backend scratch state so it fits on the stack.
pub const max_backends = 256;

/// Two independent, differently-seeded hashes of a backend id, used to
/// derive that backend's (offset, skip) permutation parameters.
fn hash1(id: u32) u64 {
    return std.hash.Wyhash.hash(0x5bd1e995, std.mem.asBytes(&id));
}
fn hash2(id: u32) u64 {
    return std.hash.Wyhash.hash(0x27d4eb2f, std.mem.asBytes(&id));
}

fn isPrime(x: usize) bool {
    if (x < 2) return false;
    if (x % 2 == 0) return x == 2;
    var d: usize = 3;
    while (d * d <= x) : (d += 2) {
        if (x % d == 0) return false;
    }
    return true;
}

/// Fills `table` with ids from `backend_ids`; slots stay `none` only for an
/// empty set. `table.len` must be prime, or a backend's `(offset + j*skip)`
/// walk revisits slots instead of permuting them. `backend_ids` must be
/// sorted, since slots are handed out in input order.
pub fn build(backend_ids: []const u32, table: []u32) void {
    std.debug.assert(isPrime(table.len));
    std.debug.assert(backend_ids.len <= max_backends);
    std.debug.assert(std.sort.isSorted(u32, backend_ids, {}, std.sort.asc(u32)));

    @memset(table, none);
    if (backend_ids.len == 0) return;

    const m = table.len;
    const n = backend_ids.len;

    var offset: [max_backends]usize = undefined;
    var skip: [max_backends]usize = undefined;
    var next: [max_backends]usize = undefined;
    for (backend_ids, 0..) |id, i| {
        offset[i] = @intCast(hash1(id) % m);
        skip[i] = @intCast(hash2(id) % (m - 1) + 1);
        next[i] = 0;
    }

    var filled: usize = 0;
    while (true) {
        for (0..n) |i| {
            // permutation[i][j] is pure in (i, j); no need to materialize
            // the paper's n*m table.
            var cand = (offset[i] + next[i] * skip[i]) % m;
            while (table[cand] != none) {
                next[i] += 1;
                std.debug.assert(next[i] < m); // holds while filled < m
                cand = (offset[i] + next[i] * skip[i]) % m;
            }
            table[cand] = backend_ids[i];
            next[i] += 1;
            filled += 1;
            if (filled == m) return;
        }
    }
}

const test_table_size = 4099;

test "empty backend set leaves every slot unassigned" {
    // An ARRAY map reads back as zeros, which is a valid backend id.
    var table: [test_table_size]u32 = undefined;
    build(&.{}, &table);
    for (table) |slot| try std.testing.expectEqual(none, slot);
}

test "every slot gets filled and distribution is even" {
    var table: [test_table_size]u32 = undefined;
    const backends = [_]u32{ 1, 2, 3, 4 };
    build(&backends, &table);

    var counts = [_]u32{0} ** 5;
    for (table) |slot| {
        try std.testing.expect(slot >= 1 and slot <= 4);
        counts[slot] += 1;
    }
    for (counts[1..]) |cnt| {
        const expected: f64 = @as(f64, @floatFromInt(test_table_size)) / 4.0;
        const ratio = @as(f64, @floatFromInt(cnt)) / expected;
        try std.testing.expect(ratio > 0.85 and ratio < 1.15);
    }
}

test "the same backend set produces the same table" {
    var a: [test_table_size]u32 = undefined;
    var b: [test_table_size]u32 = undefined;
    build(&[_]u32{ 3, 7, 11, 42 }, &a);
    build(&[_]u32{ 3, 7, 11, 42 }, &b);
    try std.testing.expectEqualSlices(u32, &a, &b);
}

test "removing a backend moves only its share of slots" {
    var before: [test_table_size]u32 = undefined;
    var after: [test_table_size]u32 = undefined;
    build(&[_]u32{ 1, 2, 3, 4 }, &before);
    build(&[_]u32{ 1, 2, 4 }, &after);

    var moved: usize = 0;
    for (before, after) |old, new| {
        try std.testing.expect(new != 3);
        if (old != new) moved += 1;
    }
    // Survivors shift a little -- the round-robin cycle got shorter.
    // `hash % n` would churn ~3/4 of the table here.
    const moved_frac = @as(f64, @floatFromInt(moved)) / test_table_size;
    try std.testing.expect(moved_frac < 0.30);
}
