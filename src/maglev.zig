//! Maglev consistent hashing (Google, NSDI'16). Builds a lookup table of
//! `table_size` slots over a set of backend ids such that:
//!   - load is spread ~evenly across backends,
//!   - when one backend is added/removed, only ~1/N of the slots change
//!     (as opposed to naive `hash % backend_count`, where nearly every flow
//!     would get remapped to a different backend).
//!
//! This is exactly the technique Katran uses in production; the eBPF
//! program just does an O(1) array lookup into whatever table we compute
//! here and push into `maglev_map`.

const std = @import("std");

/// Two independent, differently-seeded hashes of a backend id, used to
/// derive that backend's (offset, skip) permutation parameters.
fn hash1(addr: u32) u64 {
    return std.hash.Wyhash.hash(0x5bd1e995, std.mem.asBytes(&addr));
}
fn hash2(addr: u32) u64 {
    return std.hash.Wyhash.hash(0x27d4eb2f, std.mem.asBytes(&addr));
}

/// Populates `table` (length `table_size`, which must be prime for good
/// distribution) with backend ids from `backend_ids`. `table_size` must be
/// >= backend_ids.len (it always will be in practice: MAGLEV_TABLE_SIZE is
/// 4099 against at most MAX_BACKENDS_PER_VIP backends).
pub fn build(allocator: std.mem.Allocator, backend_ids: []const u32, table_size: u32, table: []i64) !void {
    std.debug.assert(table.len == table_size);
    for (table) |*slot| slot.* = -1;

    if (backend_ids.len == 0) return;

    const n = backend_ids.len;
    const permutation = try allocator.alloc(u32, n * table_size);
    defer allocator.free(permutation);
    const next = try allocator.alloc(u32, n);
    defer allocator.free(next);
    @memset(next, 0);

    for (backend_ids, 0..) |bid, i| {
        const offset: u32 = @intCast(hash1(bid) % table_size);
        const skip: u32 = @intCast(hash2(bid) % (table_size - 1) + 1);
        var j: u32 = 0;
        while (j < table_size) : (j += 1) {
            permutation[i * table_size + j] = (offset + j * skip) % table_size;
        }
    }

    var filled: u32 = 0;
    while (true) {
        for (0..n) |i| {
            var c = permutation[i * table_size + next[i]];
            while (table[c] != -1) {
                next[i] += 1;
                c = permutation[i * table_size + next[i]];
            }
            table[c] = @intCast(backend_ids[i]);
            next[i] += 1;
            filled += 1;
            if (filled == table_size) return;
        }
    }
}
