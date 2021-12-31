# mbedtls build package

[![build](https://github.com/mattnite/zig-mbedtls/actions/workflows/build.yml/badge.svg)](https://github.com/mattnite/zig-mbedtls/actions/workflows/build.yml)

## Like this project?

If you like this project or other works of mine, please consider [donating to or sponsoring me](https://github.com/sponsors/mattnite) on Github [:heart:](https://github.com/sponsors/mattnite)

## How to use

This repo contains code for your `build.zig` that can statically compile mbedtls.

### Link to your application

In order to statically link mbedtls into your application and access the bindings with a configurable import string:

```zig
const zlib = @import("path/to/mbedtls.zig");

pub fn build(b: *std.build.Builder) void {
    // ...

    const lib = mbedtls.create(b, target, mode);

    const exe = b.addExecutable("my-program", "src/main.zig");
    lib.link(exe, .{});
}
```