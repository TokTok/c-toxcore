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
        libs: []const *Compile = &.{},
    };
    // this two kind of options is to have an easy input for the common case
    const Opt = struct {
        name: []const u8,
        cs: []const []const u8,
        libs: []const *Compile,
        fn init(b: *Build, o: Options) Opt {
            const cs = if (o.c.len > 0) b.dupeStrings(&.{o.c}) else o.cs;
            const name =
                if (o.name.len > 0) o.name else if (cs.len > 0) trimRight(u8, cs[0], ".c") else "noname";
            // std.debug.print("name = {s}, {s}\n", .{ name, cs[0] });
            return Opt{ .name = name, .cs = cs, .libs = o.libs };
        }
    };
    // add object
    fn addObj(self: Relief, op: Options) [1]*Compile {
        const o = Opt.init(self.b, op);
        const c = self.b.addObject(
            .{ .name = o.name, .target = self.target, .optimize = self.optimize },
        );
        c.linkLibC();
        c.addIncludePath(.{ .path = self.subdir });
        for (o.cs) |file| {
            c.addCSourceFile(
                .{ .file = .{ .path = self.inSubdir(file) }, .flags = &.{} },
            );
        }
        for (o.libs) |l| {
            c.installLibraryHeaders(l);
            c.linkLibrary(l);
        }
        return [_]*Compile{c};
    }
    fn addGTest(self: Relief, op: Options, d: []const *Compile) *Compile {
        const o = Opt.init(self.b, op);
        const c = self.b.addExecutable(.{ .name = o.name });
        for (o.cs) |file| {
            c.addCSourceFile(
                .{ .file = .{ .path = self.inSubdir(file) }, .flags = &.{} },
            );
        }
        // we ommit duplicate dependencies
        for (0..d.len) |i| {
            var unique = true;
            for (0..i) |j| {
                if (j < i and d[i] == d[j]) {
                    unique = false;
                    break;
                }
            }
            if (unique) c.addObject(d[i]);
        }
        for (o.libs) |l| {
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

    const mem = r.addObj(.{ .c = "mem.c" });
    const util = r.addObj(.{ .c = "util.c" }) ++ mem;
    const logger = r.addObj(.{ .c = "logger.c" });
    const cmp = r.addObj(.{ .name = "cmp", .c = "../third_party/cmp/cmp.c" });
    const bin_pack = r.addObj(.{ .c = "bin_pack.c" }) ++ logger ++ cmp;
    const bin_unpack = r.addObj(.{ .c = "bin_unpack.c" }) ++ cmp;
    const crypto_core = r.addObj(.{ .c = "crypto_core.c", .libs = &.{libsodium} });
    const list = r.addObj(.{ .c = "list.c" });
    const state = r.addObj(.{ .c = "state.c" });
    const mono_time = r.addObj(.{ .c = "mono_time.c" }) ++ mem ++ util;
    const shared_key_cache = r.addObj(.{ .c = "shared_key_cache.c" }) ++ crypto_core ++ logger ++ mem ++ mono_time;
    const network = r.addObj(.{ .c = "network.c", .libs = &.{libsodium} }) ++ crypto_core ++ logger ++ mem ++ mono_time ++ util;
    const timed_auth = r.addObj(.{ .c = "timed_auth.c" }) ++ crypto_core ++ mono_time;
    const ping_array = r.addObj(.{ .c = "ping_array.c" }) ++ crypto_core ++ mem ++ mono_time ++ util;
    const LAN_discovery = r.addObj(.{ .c = "LAN_discovery.c" }) ++ network;
    const DHT = r.addObj(.{ .cs = &.{ "DHT.c", "ping.c" } }) ++ bin_pack ++ network ++ ping_array ++ LAN_discovery ++ shared_key_cache ++ state;
    const onion = r.addObj(.{ .c = "onion.c" }) ++ DHT;
    const forwarding = r.addObj(.{ .c = "forwarding.c" }) ++ network ++ timed_auth;
    const announce = r.addObj(.{ .c = "announce.c" }) ++ LAN_discovery ++ forwarding ++ shared_key_cache;
    const TCP_common = r.addObj(.{ .c = "TCP_common.c" }) ++ network;
    // TODO     copts = select({
    // "//tools/config:linux": ["-DTCP_SERVER_USE_EPOLL=1"],
    //    "//conditions:default": [],
    //}),
    const TCP_server = r.addObj(.{ .c = "TCP_server.c" }) ++ TCP_common ++ crypto_core ++ forwarding ++ list ++ mono_time ++ onion;
    const TCP_client = r.addObj(.{ .c = "TCP_client.c" }) ++ TCP_common ++ crypto_core ++ forwarding;
    const TCP_connection = r.addObj(.{ .c = "TCP_connection.c" }) ++ TCP_client;
    const net_crypto = r.addObj(.{ .c = "net_crypto.c" }) ++ DHT ++ TCP_connection ++ list;
    const onion_announce = r.addObj(.{ .c = "onion_announce.c" }) ++ DHT ++ onion;
    const group_announce = r.addObj(.{ .c = "group_announce.c" }) ++ DHT;
    const group_onion_announce = r.addObj(.{ .c = "group_announce.c" }) ++ group_announce ++ onion_announce;
    const onion_client = r.addObj(.{ .c = "onion_client.c" }) ++ group_onion_announce;
    const friend_connection = r.addObj(.{ .c = "friend_connection.c" }) ++ net_crypto ++ onion_client;
    _ = TCP_server;
    //_ = TCP_client;
    _ = announce;
    //_ = onion_announce;
    _ = friend_connection;
    // tests
    _ = r.addGTest(.{ .c = "mem_test.cc" }, &mem);
    _ = r.addGTest(.{ .c = "util_test.cc" }, &(util ++ crypto_core));
    _ = r.addGTest(.{ .c = "bin_pack_test.cc" }, &(bin_pack ++ bin_unpack));
    _ = r.addGTest(.{ .c = "crypto_core_test.cc" }, &crypto_core);
    _ = r.addGTest(.{ .c = "list_test.cc" }, &list);
    _ = r.addGTest(.{ .c = "mono_time_test.cc" }, &mono_time);
    _ = r.addGTest(.{ .c = "network_test.cc" }, &network);
    _ = r.addGTest(.{ .c = "ping_array_test.cc" }, &ping_array);
    _ = r.addGTest(.{ .c = "DHT_test.cc" }, &DHT);
    // TODO DHT_fuzz_test
    // TODO forwarding_fuzz_test
    _ = r.addGTest(.{ .c = "TCP_connection_test.cc" }, &TCP_connection);
    _ = r.addGTest(.{ .c = "group_announce_test.cc" }, &group_announce);
    // TODO group_announce_fuzz_test
    // duplicated symbols !!
    // _ = r.addGTest(.{ .c = "friend_connection_test.cc" }, &friend_connection);
}
