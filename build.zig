const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const fs = std.fs;
const mem = std.mem;
const LibExeObjStep = std.build.LibExeObjStep;
const Target = std.Target;

pub fn build(b: *std.build.Builder) !void {
    const root_path = b.pathFromRoot(".");
    var cwd = try fs.openDirAbsolute(root_path, .{});
    defer cwd.close();

    var target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    var build_static = b.option(bool, "static", "Build libtoxcore as a static library.") orelse true;
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
        .{
            .target = target,
            .optimize = optimize,
            .static = true,
            .shared = false,
        },
    );

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
        lib.linkLibrary(libsodium_dep.artifact("sodium"));

        var allocator = heap.page_allocator;
        const src_path = "toxcore";
        const src_dir = try fs.Dir.openIterableDir(cwd, src_path, .{ .no_follow = true });
        var walker = try src_dir.walk(allocator);
        while (try walker.next()) |entry| {
            const name = entry.basename;
            if (mem.endsWith(u8, name, ".c")) {
                const full_path = try fmt.allocPrint(allocator, "{s}/{s}", .{ src_path, entry.path });
                lib.addCSourceFiles(&.{full_path}, &.{});
            }
        }
        lib.addCSourceFiles(&.{"third_party/cmp/cmp.c"}, &.{});
        if (lib.isStaticLibrary()) {
            var toxcore_zig = b.addTranslateC(.{
                .optimize = optimize,
                .target = target,
                .source_file = .{ .path = "toxcore/tox.h" },
            });
            toxcore_zig.addIncludeDir("toxcore");
            //_ = b.addModule(
            //    "toxcore",
            //    .{ .source_file = .{ .generated = &translate_header.output_file } },
            //);
            //_ = b.addInstallHeaderFile("toxcore/tox.h", "tox.h");
            const toxcore_zig_step = b.step("toxcoreWrapper", "Build Zig wrapper around toxcore API");
            //lib.step.dependOn(&translate_header.step);
            const f: std.build.FileSource = .{ .generated = &toxcore_zig.output_file };
            toxcore_zig_step.dependOn(&toxcore_zig.step);
            toxcore_zig_step.dependOn(&b.addInstallFile(f, "toxcore.zig").step);
        }
    }
}
