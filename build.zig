const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const fs = std.fs;
//const mem = std.mem;
const LibExeObjStep = std.build.LibExeObjStep;
const Target = std.Target;

fn thisDir() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}
fn ensureDependencySubmodule(allocator: std.mem.Allocator, path: []const u8) !void {
    if (std.process.getEnvVarOwned(allocator, "NO_ENSURE_SUBMODULES")) |no_ensure_submodules| {
        defer allocator.free(no_ensure_submodules);
        if (std.mem.eql(u8, no_ensure_submodules, "true")) return;
    } else |_| {}
    var child = std.ChildProcess.init(&.{ "git", "submodule", "update", "--init", path }, allocator);
    child.cwd = (comptime thisDir());
    child.stderr = std.io.getStdErr();
    child.stdout = std.io.getStdOut();

    _ = try child.spawnAndWait();
}

pub fn build(b: *std.build.Builder) !void {
    const root_path = b.pathFromRoot(".");
    var cwd = try fs.openDirAbsolute(root_path, .{});
    defer cwd.close();

    var target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const build_static = b.option(bool, "static", "Build libtoxcore as a static library.") orelse true;
    const build_shared = b.option(bool, "shared", "Build libtoxcore as a shared library.") orelse true;

    const static_lib = b.addStaticLibrary(.{
        .name = "toxcore",
        .target = target,
        .optimize = optimize,
    });
    const shared_lib = b.addSharedLibrary(.{
        .name = if (target.isWindows()) "toxcore_shared" else "toxcore",
        .target = target,
        .optimize = optimize,
    });

    const libsodium_dep = b.dependency(
        "libsodium",
        .{ .target = target, .optimize = optimize, .static = true, .shared = false },
    );

    const gtest_dep = b.dependency(
        "gtest",
        .{
            .target = target,
            .optimize = optimize,
        },
    );
    ensureDependencySubmodule(b.allocator, "third_party/cmp") catch unreachable;

    // work out which libraries we are building
    var libs = std.ArrayList(*LibExeObjStep).init(b.allocator);
    defer libs.deinit();
    if (build_static) {
        try libs.append(static_lib);
    }
    if (build_shared) {
        try libs.append(shared_lib);
    }
    for (libs.items) |lib| {
        if (lib.isDynamicLibrary() and
            !(target.isDarwin() or target.isDragonFlyBSD() or target.isFreeBSD() or
            target.isLinux() or target.isNetBSD() or target.isOpenBSD() or target.isWindows()))
        {
            continue;
        }
        if (optimize != .Debug and !target.isWindows() and !lib.isStaticLibrary()) {
            lib.strip = true;
        }
        b.installArtifact(lib);
        lib.installHeader("toxcore/tox.h", "tox.h");
        lib.linkLibC();
        lib.installHeadersDirectory("toxcore", "toxcore");
        lib.linkLibrary(libsodium_dep.artifact("sodium"));

        const allocator = heap.page_allocator;
        const src_path = "toxcore";
        const src_dir = try fs.Dir.openDir(cwd, src_path, .{ .iterate = true, .no_follow = true });
        var walker = try src_dir.walk(allocator);
        while (try walker.next()) |entry| {
            const name = entry.basename;
            if (std.mem.endsWith(u8, name, ".c")) {
                const full_path = try fmt.allocPrint(allocator, "{s}/{s}", .{ src_path, entry.path });
                lib.addCSourceFile(.{
                    .file = .{ .path = full_path },
                    .flags = &.{},
                });
            }
        }
        lib.addCSourceFile(.{
            .file = .{ .path = "third_party/cmp/cmp.c" },
            .flags = &.{},
        });
    }
    // build zig wrapper
    var toxcore_zig = b.addTranslateC(.{
        .optimize = optimize,
        .target = target,
        .source_file = .{ .path = "toxcore/tox.h" },
    });
    toxcore_zig.addIncludeDir("toxcore");
    const toxcore_zig_step = b.step("toxcore_zig", "Build Zig wrapper around toxcore API");
    const toxcore_zig_file = std.build.FileSource{ .generated = &toxcore_zig.output_file };
    toxcore_zig_step.dependOn(&toxcore_zig.step);
    toxcore_zig_step.dependOn(&b.addInstallFile(toxcore_zig_file, "toxcore.zig").step);

    // build tests
    const gtest_lib = gtest_dep.artifact("gtest");
    const gtest_main = gtest_dep.artifact("gtest-main");

    const mem = b.addObject(.{ .name = "mem", .target = target, .optimize = optimize });
    mem.addCSourceFile(.{ .file = .{ .path = "toxcore/mem.c" }, .flags = &.{} });
    mem.addIncludePath(.{ .path = "toxcore" });
    mem.linkLibC();
    const mem_test = b.addExecutable(.{ .name = "mem_test" });
    mem_test.addCSourceFile(.{ .file = .{ .path = "toxcore/mem_test.cc" }, .flags = &.{} });
    mem_test.addObject(mem);
    mem_test.installLibraryHeaders(gtest_lib);
    mem_test.linkLibrary(gtest_lib);
    mem_test.linkLibrary(gtest_main);
    mem_test.linkLibC();
    b.installArtifact(mem_test);
}
