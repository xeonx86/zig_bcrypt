const std = @import("std");

const c = @cImport({
    @cInclude("windows.h");
    @cInclude("bcrypt.h");
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    var args = try std.process.ArgIterator.initWithAllocator(alloc);
    defer args.deinit();

    _ = args.next();
    const fname = args.next();

    var buff: []u8 = undefined;
    defer alloc.free(buff);

    if (fname) |filename| {
        const file = try std.fs.cwd().openFile(filename, .{ .mode = .read_only });
        const file_size = try file.getEndPos();
        buff = try alloc.alloc(u8, file_size);
        _ = try file.readAll(buff);
        file.close();
    } else {
        std.debug.print("file not found\n", .{});
        std.process.exit(0);
    }

    std.debug.print("{any}\n", .{std.mem.asBytes(buff.ptr)});

    var secret: [32]u8 = undefined;
    @memset(secret[0..], 0);
    var iv: [16]u8 = undefined;
    @memset(iv[0..], 0);

    var iv_copy: [16]u8 = undefined;

    const random_alg_id: c.LPCWSTR = @ptrCast(try std.unicode.utf8ToUtf16LeAlloc(alloc, "RNG\x00"));
    var random_alg_handle: c.BCRYPT_ALG_HANDLE = null;
    var status = c.BCryptOpenAlgorithmProvider(&random_alg_handle, random_alg_id, null, 0);
    if (status != 0) {
        std.debug.print("BCryptOpenAlgorithmProvider failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    status = c.BCryptGenRandom(random_alg_handle, &secret, 32, 0);
    status = c.BCryptGenRandom(random_alg_handle, &iv, 16, 0);
    if (status != 0) {
        std.debug.print("BCryptGenRandom failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    status = c.BCryptCloseAlgorithmProvider(random_alg_handle, 0);
    if (status != 0) {
        std.debug.print("BCryptCloseAlgorithmProvider failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    var encryption_alg_handle: c.BCRYPT_ALG_HANDLE = null;
    const ecryption__alg_id: c.LPCWSTR = @ptrCast(try std.unicode.utf8ToUtf16LeAlloc(alloc, "AES\x00"));

    status = c.BCryptOpenAlgorithmProvider(&encryption_alg_handle, ecryption__alg_id, null, 0);
    if (status != 0) {
        std.debug.print("BCryptOpenAlgorithmProvider failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    const property_name: c.LPCWSTR = @ptrCast(try std.unicode.utf8ToUtf16LeAlloc(alloc, "ChainingMode\x00"));
    const property_value: c.PUCHAR = @ptrCast(try std.unicode.utf8ToUtf16LeAlloc(alloc, "ChainingModeCBC\x00"));

    status = c.BCryptSetProperty(encryption_alg_handle, property_name, property_value, 32, 0);
    if (status != 0) {
        std.debug.print("BCryptSetProperty failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    var encryption_key_handle: c.BCRYPT_KEY_HANDLE = null;
    status = c.BCryptGenerateSymmetricKey(encryption_alg_handle, &encryption_key_handle, null, 0, secret[0..].ptr, 32, 0);
    if (status != 0) {
        std.debug.print("BCryptGenerateSymmetricKey failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    var export_key_buff_len: c.ULONG = 0;
    const key_data_type: c.LPCWSTR = @ptrCast(try std.unicode.utf8ToUtf16LeAlloc(alloc, "KeyDataBlob\x00"));
    status = c.BCryptExportKey(encryption_key_handle, null, key_data_type, null, 0, &export_key_buff_len, 0);
    if (status != 0) {
        std.debug.print("BCryptExportKey failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    const key = try alloc.alloc(u8, export_key_buff_len);
    defer alloc.free(key);
    var cb_result: c.ULONG = 0;
    @memcpy(iv_copy[0..], iv[0..]);
    status = c.BCryptExportKey(encryption_key_handle, null, key_data_type, @ptrCast(key), export_key_buff_len, &cb_result, 0);
    if (status != 0) {
        std.debug.print("BCryptExportKey failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    var encryption_buffer_len: c.ULONG = 0;
    status = c.BCryptEncrypt(encryption_key_handle, buff.ptr, @intCast(buff.len), null, iv[0..].ptr, iv.len, 0, 0, &encryption_buffer_len, c.BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        std.debug.print("BCryptEncrypt (get needed len) failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    const enc_buff = try alloc.alloc(u8, encryption_buffer_len);

    status = c.BCryptEncrypt(encryption_key_handle, buff.ptr, @intCast(buff.len), null, iv[0..].ptr, iv.len, @ptrCast(enc_buff), encryption_buffer_len, &cb_result, c.BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        std.debug.print("BCryptEncrypt failed with error: {d}\n", .{c.GetLastError()});
        std.process.exit(0);
    }

    const out_file = try std.fs.cwd().createFile("encrypted.bin", .{});
    _ = try out_file.writeAll(enc_buff);
    out_file.close();

    const key_file = try std.fs.cwd().createFile("key.bin", .{});
    _ = try key_file.writeAll(key[12..]);
    key_file.close();

    const iv_file = try std.fs.cwd().createFile("iv.bin", .{});
    _ = try iv_file.writeAll(iv_copy[0..]);
    iv_file.close();
}
