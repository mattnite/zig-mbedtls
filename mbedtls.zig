const std = @import("std");
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}

fn pathJoinRoot(comptime components: []const []const u8) []const u8 {
    var ret = root();
    inline for (components) |component|
        ret = ret ++ std.fs.path.sep_str ++ component;

    return ret;
}

pub const include_dir = pathJoinRoot(&.{ "mbedtls", "include" });
const library_include = pathJoinRoot(&.{ "mbedtls", "library" });

pub const Library = struct {
    step: *LibExeObjStep,

    pub fn link(self: Library, other: *LibExeObjStep) void {
        other.addIncludeDir(include_dir);
        other.linkLibrary(self.step);
    }
};

pub fn create(b: *Builder, target: std.zig.CrossTarget, mode: std.builtin.Mode) Library {
    const ret = b.addStaticLibrary("mbedtls", null);
    ret.setTarget(target);
    ret.setBuildMode(mode);
    ret.addIncludeDir(include_dir);
    ret.addIncludeDir(library_include);

    // not sure why, but mbedtls has runtime issues when it's not built as
    // release-small or with the -Os flag, definitely need to figure out what's
    // going on there
    ret.addCSourceFiles(srcs, &.{"-Os"});
    ret.linkLibC();

    if (target.isWindows())
        ret.linkSystemLibrary("ws2_32");

    return Library{ .step = ret };
}

const srcs = blk: {
    @setEvalBranchQuota(4000);
    var ret = &.{
        pathJoinRoot(&.{ "mbedtls", "library", "certs.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pkcs11.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "x509.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "x509_create.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "x509_crl.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "x509_crt.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "x509_csr.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "x509write_crt.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "x509write_csr.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "debug.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "net_sockets.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_cache.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_ciphersuites.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_cli.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_cookie.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_msg.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_srv.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_ticket.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_tls13_keys.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ssl_tls.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "aes.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "aesni.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "arc4.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "aria.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "asn1parse.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "asn1write.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "base64.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "bignum.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "blowfish.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "camellia.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ccm.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "chacha20.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "chachapoly.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "cipher.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "cipher_wrap.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "cmac.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ctr_drbg.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "des.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "dhm.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ecdh.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ecdsa.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ecjpake.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ecp.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ecp_curves.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "entropy.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "entropy_poll.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "error.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "gcm.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "havege.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "hkdf.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "hmac_drbg.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "md2.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "md4.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "md5.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "md.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "memory_buffer_alloc.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "mps_reader.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "mps_trace.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "nist_kw.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "oid.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "padlock.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pem.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pk.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pkcs12.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pkcs5.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pkparse.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pk_wrap.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "pkwrite.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "platform.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "platform_util.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "poly1305.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_aead.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_cipher.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_client.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_driver_wrappers.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_ecp.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_hash.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_mac.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_rsa.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_se.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_slot_management.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_crypto_storage.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "psa_its_file.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "ripemd160.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "rsa.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "rsa_internal.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "sha1.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "sha256.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "sha512.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "threading.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "timing.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "version.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "version_features.c" }),
        pathJoinRoot(&.{ "mbedtls", "library", "xtea.c" }),
    };
    break :blk ret;
};
