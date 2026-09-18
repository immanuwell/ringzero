const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ringzero",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.root_module.addIncludePath(b.path("bpf"));
    exe.root_module.linkSystemLibrary("bpf", .{});
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run ringzero");
    run_step.dependOn(&run_cmd.step);

    const mod_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // maglev.zig imports nothing but std, so it gets its own target. Whether
    // an imported file's tests are collected depends on how the root module
    // happens to reference it; this way they run regardless, and on a machine
    // without libbpf.
    const maglev_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/maglev.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_maglev_tests = b.addRunArtifact(maglev_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_maglev_tests.step);
}
