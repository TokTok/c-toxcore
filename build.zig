const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const fs = std.fs;
const Build = std.Build;
const Step = Build.Step;
const Compile = Step.Compile;
const trimRight = std.mem.trimRight;
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

const Relief = struct {
    b: *Build,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
    subdir: []const u8,
    gtest_lib: *Compile,
    gtest_main: *Compile,

    fn inSubdir(self: Relief, file: []const u8) []const u8 {
        const p = self.b.pathJoin(&.{ self.subdir, file });
        //std.debug.print("in subdir:{s},{s},{s}\n", .{ self.subdir, file, p });
        return p[0..];
    }
    pub const Options = struct {
        name: []const u8 = "", // if empty then the stem of first c file
        c: []const u8 = "", // if not empty then only one c file
        cs: []const []const u8 = &.{}, // possibly multiple c files
        l: ?*Compile = null, // one lib
        ls: []const *Compile = &.{}, // or possibly more libs
    };
    // this two kind of options is to have an easy input for the common case
    const Opt = struct {
        name: []const u8,
        cs: []const []const u8,
        ls: []const *Compile,
        fn init(b: *Build, o: Options) Opt {
            const cs = if (o.c.len > 0) b.dupeStrings(&.{o.c}) else o.cs;
            const name =
                if (o.name.len > 0) o.name else if (cs.len > 0) trimRight(u8, cs[0], ".c") else "noname";
            const ls = if (o.l) |l_| blk: {
                break :blk b.allocator.dupe(*Compile, &.{l_}) catch unreachable;
            } else o.ls;
            // std.debug.print("name = {s}, {s}\n", .{ name, cs[0] });
            return Opt{ .name = name, .cs = cs, .ls = ls };
        }
    };
    // add lib
    fn lib(self: Relief, op: Options) *Compile {
        const o = Opt.init(self.b, op);
        const c = self.b.addStaticLibrary( //addObject(
            .{ .name = o.name, .target = self.target, .optimize = self.optimize },
        );
        c.linkLibC();
        c.addIncludePath(.{ .path = self.subdir });
        for (o.cs) |file| {
            c.addCSourceFile(
                .{ .file = .{ .path = self.inSubdir(file) }, .flags = &.{} },
            );
        }
        for (o.ls) |l| {
            c.installLibraryHeaders(l);
            c.linkLibrary(l);
        }
        return c;
    }
    fn gtest(self: Relief, op: Options) *Compile {
        const o = Opt.init(self.b, op);
        const c = self.b.addExecutable(.{ .name = o.name });
        for (o.cs) |file| {
            c.addCSourceFile(
                .{ .file = .{ .path = self.inSubdir(file) }, .flags = &.{} },
            );
        }
        // we ommit duplicate dependencies
        // for (0..d.len) |i| {
        //     var unique = true;
        //     for (0..i) |j| {
        //         if (j < i and d[i] == d[j]) {
        //             unique = false;
        //             break;
        //         }
        //     }
        //     if (unique) c.linkLibrary(d[i]); // c.addObject(d[i]);
        // }
        for (o.ls) |l| {
            c.installLibraryHeaders(l);
            c.linkLibrary(l);
        }
        c.installLibraryHeaders(self.gtest_lib);
        c.linkLibrary(self.gtest_lib);
        c.linkLibrary(self.gtest_main);
        c.linkLibC();
        self.b.installArtifact(c);
        return c;
    }
};

pub fn build(b: *std.build.Builder) !void {
    const root_path = b.pathFromRoot(".");
    var cwd = try fs.openDirAbsolute(root_path, .{});
    defer cwd.close();

    const target = b.standardTargetOptions(.{});
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
    const libsodium = libsodium_dep.artifact("sodium");

    const gtest_dep = b.dependency(
        "gtest",
        .{
            .target = target,
            .optimize = optimize,
        },
    );

    ensureDependencySubmodule(b.allocator, "third_party/cmp") catch unreachable;

    const r = Relief{
        .b = b,
        .target = target,
        .optimize = optimize,
        .subdir = "toxcore",
        .gtest_lib = gtest_dep.artifact("gtest"),
        .gtest_main = gtest_dep.artifact("gtest-main"),
    };

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
        lib.linkLibrary(libsodium);

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

    const mem = r.lib(.{ .c = "mem.c" });
    const util = r.lib(.{ .c = "util.c", .l = mem });
    const logger = r.lib(.{ .c = "logger.c" });
    const cmp = r.lib(.{ .name = "cmp", .c = "../third_party/cmp/cmp.c" });
    const bin_pack = r.lib(.{ .c = "bin_pack.c", .ls = &.{ logger, cmp } });
    const bin_unpack = r.lib(.{ .c = "bin_unpack.c", .l = cmp });
    const crypto_core = r.lib(.{ .c = "crypto_core.c", .l = libsodium });
    const list = r.lib(.{ .c = "list.c" });
    const state = r.lib(.{ .c = "state.c" });
    const mono_time = r.lib(.{ .c = "mono_time.c", .ls = &.{ mem, util } });
    const shared_key_cache = r.lib(.{
        .c = "shared_key_cache.c",
        .ls = &.{ crypto_core, logger, mem, mono_time },
    });
    const network = r.lib(.{
        .c = "network.c",
        .ls = &.{ libsodium, crypto_core, logger, mem, mono_time, util },
    });
    const timed_auth = r.lib(.{ .c = "timed_auth.c", .ls = &.{ crypto_core, mono_time } });
    const ping_array = r.lib(.{ .c = "ping_array.c", .ls = &.{ crypto_core, mem, mono_time, util } });
    const LAN_discovery = r.lib(.{ .c = "LAN_discovery.c", .l = network });
    const DHT = r.lib(.{
        .cs = &.{ "DHT.c", "ping.c" },
        .ls = &.{ bin_pack, network, ping_array, LAN_discovery, shared_key_cache, state },
    });
    const onion = r.lib(.{ .c = "onion.c", .l = DHT });
    const forwarding = r.lib(.{ .c = "forwarding.c", .ls = &.{ network, timed_auth } });
    const announce = r.lib(.{ .c = "announce.c", .ls = &.{ LAN_discovery, forwarding, shared_key_cache } });
    const TCP_common = r.lib(.{ .c = "TCP_common.c", .l = network });
    // TODO     copts = select({
    // "//tools/config:linux": ["-DTCP_SERVER_USE_EPOLL=1"],
    //    "//conditions:default": [],
    //}),
    const TCP_server = r.lib(.{
        .c = "TCP_server.c",
        .ls = &.{ TCP_common, crypto_core, forwarding, list, mono_time, onion },
    });
    const TCP_client = r.lib(.{ .c = "TCP_client.c", .ls = &.{ TCP_common, crypto_core, forwarding } });
    const TCP_connection = r.lib(.{ .c = "TCP_connection.c", .l = TCP_client });
    const net_crypto = r.lib(.{ .c = "net_crypto.c", .ls = &.{ DHT, TCP_connection, list } });
    const onion_announce = r.lib(.{ .c = "onion_announce.c", .ls = &.{ DHT, onion } });
    const group_announce = r.lib(.{ .c = "group_announce.c", .l = DHT });
    const group_onion_announce = r.lib(.{ .c = "group_onion_announce.c", .ls = &.{ group_announce, onion_announce } });
    const onion_client = r.lib(.{ .c = "onion_client.c", .l = group_onion_announce });
    const friend_connection = r.lib(.{ .c = "friend_connection.c", .ls = &.{ net_crypto, onion_client } });
    const friend_requests = r.lib(.{ .c = "friend_requests.c", .l = friend_connection });
    const group_moderation = r.lib(.{ .c = "group_moderation.c", .ls = &.{ crypto_core, network, libsodium } });
    const Messenger = r.lib(.{
        .cs = &.{ "Messenger.c", "group_chats.c", "group_connection.c", "group_pack.c" },
        .ls = &.{ DHT, onion_client, TCP_connection, TCP_server, friend_requests, group_moderation, announce, bin_unpack },
    });
    const group = r.lib(.{ .c = "group.c", .l = Messenger });
    // TODO "//c-toxcore/toxencryptsave:defines",
    const tox = r.lib(.{ .cs = &.{ "tox.c", "tox_api.c", "tox_private.c" }, .ls = &.{ Messenger, group } });
    const tox_unpack = r.lib(.{ .c = "tox_unpack.c", .l = Messenger });
    const tox_events = r.lib(.{
        .cs = &.{
            "tox_events.c",
            "events/conference_connected.c",
            "events/conference_invite.c",
            "events/conference_message.c",
            "events/conference_peer_list_changed.c",
            "events/conference_peer_name.c",
            "events/conference_title.c",
            "events/events_alloc.c",
            "events/file_chunk_request.c",
            "events/file_recv.c",
            "events/file_recv_chunk.c",
            "events/file_recv_control.c",
            "events/friend_connection_status.c",
            "events/friend_lossless_packet.c",
            "events/friend_lossy_packet.c",
            "events/friend_message.c",
            "events/friend_name.c",
            "events/friend_read_receipt.c",
            "events/friend_request.c",
            "events/friend_status.c",
            "events/friend_status_message.c",
            "events/friend_typing.c",
            "events/self_connection_status.c",
        },
        .ls = &.{ tox, tox_unpack },
    });
    const tox_dispatch = r.lib(.{ .c = "tox_dispatch.c", .l = tox_events });
    const toxcore = tox_dispatch;

    // tests
    _ = r.gtest(.{ .c = "mem_test.cc", .l = mem });
    _ = r.gtest(.{ .c = "util_test.cc", .ls = &.{ util, crypto_core } });
    _ = r.gtest(.{ .c = "bin_pack_test.cc", .ls = &.{ bin_pack, bin_unpack } });
    _ = r.gtest(.{ .c = "crypto_core_test.cc", .l = crypto_core });
    _ = r.gtest(.{ .c = "list_test.cc", .l = list });
    _ = r.gtest(.{ .c = "mono_time_test.cc", .l = mono_time });
    _ = r.gtest(.{ .c = "network_test.cc", .l = network });
    _ = r.gtest(.{ .c = "ping_array_test.cc", .l = ping_array });
    _ = r.gtest(.{ .c = "DHT_test.cc", .l = DHT });
    // TODO DHT_fuzz_test
    // TODO forwarding_fuzz_test
    _ = r.gtest(.{ .c = "TCP_connection_test.cc", .l = TCP_connection });
    _ = r.gtest(.{ .c = "group_announce_test.cc", .l = group_announce });
    // TODO group_announce_fuzz_test
    // duplicated symbols !!
    _ = r.gtest(.{ .c = "friend_connection_test.cc", .l = friend_connection });
    _ = r.gtest(.{ .c = "group_moderation_test.cc", .l = group_moderation });
    // TODO group_moderation_fuzz_test
    _ = r.gtest(.{ .c = "tox_test.cc", .l = tox });
    _ = r.gtest(.{ .c = "tox_events_test.cc", .l = tox_events });
    // TODO tox_events_fuzz_test
}
