const std = @import("std");
const Build = std.Build;
const Step = Build.Step;
const Compile = Step.Compile;
const Dependency = Build.Dependency;
const fs = std.fs;

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libsodium_dep = b.dependency(
        "libsodium",
        .{ .target = target, .optimize = optimize, .static = true, .shared = false },
    );
    const libsodium = libsodium_dep.artifact("sodium");

    const win_build = target.result.isMinGW();
    var winpthreads_dep: ?*Dependency = null;
    var winpthreads: ?*Compile = null;
    if (win_build) {
        winpthreads_dep = b.dependency(
            "winpthreads",
            .{ .target = target, .optimize = optimize },
        );
        winpthreads =
            winpthreads_dep.?.artifact("winpthreads");
    }
    const gt_dep = b.dependency("gtest", .{ .target = target, .optimize = optimize });
    const cmp_dep = b.dependency("cmp", .{});
    // we copy the third_party dependencies into the source tree
    // not an ideal solution but we need them there and git
    // submodule want work for zig dependency snapshots.
    // we do the copy only if the file does not exist at the
    // target position
    const copy_files = b.addWriteFiles();
    inline for (.{ "cmp.h", "cmp.c" }) |file| {
        const rpath = b.pathJoin(&.{ "third_party/cmp", file });
        const apath = b.pathFromRoot(rpath);
        if (fs.accessAbsolute(apath, .{})) |_| {} else |_| {
            // if the file does not exist we copy it
            _ = copy_files.addCopyFileToSource(
                .{ .dependency = .{ .dependency = cmp_dep, .sub_path = file } },
                rpath,
            );
        }
    }

    const lib_src_files = &.{
        "third_party/cmp/cmp.c",
        "toxcore/announce.c",
        "toxcore/bin_pack.c",
        "toxcore/bin_unpack.c",
        "toxcore/ccompat.c",
        "toxcore/crypto_core.c",
        "toxcore/DHT.c",
        "toxcore/forwarding.c",
        "toxcore/friend_connection.c",
        "toxcore/friend_requests.c",
        "toxcore/group_announce.c",
        "toxcore/group.c",
        "toxcore/group_chats.c",
        "toxcore/group_connection.c",
        "toxcore/group_moderation.c",
        "toxcore/group_onion_announce.c",
        "toxcore/group_pack.c",
        "toxcore/LAN_discovery.c",
        "toxcore/list.c",
        "toxcore/logger.c",
        "toxcore/mem.c",
        "toxcore/Messenger.c",
        "toxcore/mono_time.c",
        "toxcore/net_crypto.c",
        "toxcore/network.c",
        "toxcore/onion_announce.c",
        "toxcore/onion.c",
        "toxcore/onion_client.c",
        "toxcore/ping_array.c",
        "toxcore/ping.c",
        "toxcore/shared_key_cache.c",
        "toxcore/state.c",
        "toxcore/TCP_client.c",
        "toxcore/TCP_common.c",
        "toxcore/TCP_connection.c",
        "toxcore/TCP_server.c",
        "toxcore/timed_auth.c",
        "toxcore/tox_api.c",
        "toxcore/tox.c",
        "toxcore/tox_dispatch.c",
        "toxcore/tox_events.c",
        "toxcore/tox_private.c",
        "toxcore/tox_unpack.c",
        "toxcore/util.c",
        "toxcore/events/conference_connected.c",
        "toxcore/events/conference_invite.c",
        "toxcore/events/conference_message.c",
        "toxcore/events/conference_peer_list_changed.c",
        "toxcore/events/conference_peer_name.c",
        "toxcore/events/conference_title.c",
        "toxcore/events/events_alloc.c",
        "toxcore/events/file_chunk_request.c",
        "toxcore/events/file_recv.c",
        "toxcore/events/file_recv_chunk.c",
        "toxcore/events/file_recv_control.c",
        "toxcore/events/friend_connection_status.c",
        "toxcore/events/friend_lossless_packet.c",
        "toxcore/events/friend_lossy_packet.c",
        "toxcore/events/friend_message.c",
        "toxcore/events/friend_name.c",
        "toxcore/events/friend_read_receipt.c",
        "toxcore/events/friend_request.c",
        "toxcore/events/friend_status.c",
        "toxcore/events/friend_status_message.c",
        "toxcore/events/friend_typing.c",
        "toxcore/events/self_connection_status.c",
    };

    const build_static = b.option(bool, "static", "Build c-toxcore as a static library.") orelse true;
    const build_shared = b.option(bool, "shared", "Build c-toxcore as a shared library.") orelse true;

    const static_lib = b.addStaticLibrary(.{ .name = "toxcore", .target = target, .optimize = optimize });
    const shared_lib = b.addSharedLibrary(.{
        .name = if (win_build) "toxcore_shared" else "toxcore",
        .target = target,
        .optimize = optimize,
        .strip = optimize != .Debug and !win_build,
    });
    // work out which libraries we are building
    var libs = std.ArrayList(*Compile).init(b.allocator);
    defer libs.deinit();
    if (build_static) {
        try libs.append(static_lib);
    }
    if (build_shared) {
        try libs.append(shared_lib);
    }
    for (libs.items) |lib| {
        if (lib.isDynamicLibrary() and
            !(target.result.isDarwin() or target.result.isBSD() or target.result.isGnu() or
            target.result.isAndroid()))
        {
            continue;
        }
        b.installArtifact(lib);
        lib.linkLibC();
        lib.installHeadersDirectory("toxcore", "toxcore");
        lib.linkLibrary(libsodium);
        if (winpthreads) |w| {
            lib.linkLibrary(w);
            if (winpthreads_dep) |d|
                lib.addIncludePath(d.path("include"));
            lib.linkSystemLibrary("ws2_32");
            lib.linkSystemLibrary("iphlpapi");
        }
        lib.addCSourceFiles(.{ .files = lib_src_files });
        lib.step.dependOn(&copy_files.step);
    }

    // ----- build zig code for header files
    const toxcore_zig_step = b.step("toxcore_zig", "Build Zig wrappers around toxcore API");
    {
        const toxcore_zig = b.addTranslateC(.{
            .optimize = optimize,
            .target = target,
            .source_file = .{ .path = "toxcore/tox.h" },
        });
        toxcore_zig.addIncludeDir("toxcore");
        toxcore_zig_step.dependOn(&toxcore_zig.step);
        toxcore_zig_step.dependOn(&b.addInstallFile(
            std.Build.LazyPath{ .generated = &toxcore_zig.output_file },
            "toxcore.zig",
        ).step);
    }
    {
        const network_zig = b.addTranslateC(.{
            .optimize = optimize,
            .target = target,
            .source_file = .{ .path = "toxcore/network.h" },
        });
        network_zig.addIncludeDir("toxcore");
        toxcore_zig_step.dependOn(&network_zig.step);
        toxcore_zig_step.dependOn(&b.addInstallFile(
            std.Build.LazyPath{ .generated = &network_zig.output_file },
            "network.zig",
        ).step);
    }
    if (build_static) {
        // ----- gtest ---------------
        const gtest_lib = gt_dep.artifact("gtest");
        const gtest_main = gt_dep.artifact("gtest-main");
        const gtest_files = &.{
            "toxcore/bin_pack_test.cc",
            "toxcore/crypto_core_test.cc",
            "toxcore/crypto_core_test_util.cc",
            //"toxcore/DHT_test.cc",
            "toxcore/friend_connection_test.cc",
            "toxcore/group_announce_test.cc",
            "toxcore/group_moderation_test.cc",
            "toxcore/list_test.cc",
            "toxcore/mem_test.cc",
            "toxcore/mono_time_test.cc",
            "toxcore/network_test.cc",
            "toxcore/ping_array_test.cc",
            "toxcore/TCP_connection_test.cc",
            "toxcore/tox_events_test.cc",
            "toxcore/tox_test.cc",
            "toxcore/util_test.cc",
        };
        const gtest = b.addExecutable(.{
            .name = "gtest",
            .target = target,
            .optimize = optimize,
        });
        gtest.addCSourceFiles(.{ .files = gtest_files });
        gtest.installLibraryHeaders(static_lib);
        gtest.linkLibrary(static_lib);
        gtest.installLibraryHeaders(gtest_lib);
        gtest.linkLibrary(gtest_lib);
        gtest.linkLibrary(gtest_main);
        gtest.linkLibC();
        if (winpthreads) |w| {
            gtest.linkLibrary(w);
            if (winpthreads_dep) |d|
                gtest.addIncludePath(d.path("include"));
            gtest.linkSystemLibrary("ws2_32");
            gtest.linkSystemLibrary("iphlpapi");
        }
        b.installArtifact(gtest);
        // ----- gmock---------------
        const gmock_lib = gt_dep.artifact("gmock");
        const gmock_main = gt_dep.artifact("gmock-main");
        const gmock_files = &.{
            "toxcore/DHT_test.cc",
            "toxcore/DHT_test_util.cc",
            "toxcore/network_test_util.cc",
            "toxcore/crypto_core_test_util.cc",
        };
        const gmock = b.addExecutable(.{
            .name = "gmock",
            .target = target,
            .optimize = optimize,
        });
        gmock.addCSourceFiles(.{ .files = gmock_files });
        gmock.installLibraryHeaders(static_lib);
        gmock.linkLibrary(static_lib);
        gmock.installLibraryHeaders(gmock_lib);
        gmock.linkLibrary(gmock_lib);
        gmock.linkLibrary(gmock_main);
        gmock.linkLibC();
        if (winpthreads) |w| {
            gmock.linkLibrary(w);
            if (winpthreads_dep) |d|
                gmock.addIncludePath(d.path("include"));
            gmock.linkSystemLibrary("ws2_32");
            gmock.linkSystemLibrary("iphlpapi");
        }
        b.installArtifact(gmock);
    }
}
