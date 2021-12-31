const std = @import("std");
const mbedtls = @import("mbedtls.zig");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const lib = mbedtls.create(b, target, mode);
    lib.step.install();
}
