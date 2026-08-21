const std = @import("std");
const bzip2z = @import("bzip2z");

pub fn decompressStream(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    max_output_size: u64,
) !void {
    const max_output_bytes = std.math.cast(usize, max_output_size) orelse
        return error.FirmwareTooLarge;
    bzip2z.bzip2.decompressStream(allocator, reader, writer, .{
        .stream_mode = .single,
        .max_output_bytes = max_output_bytes,
    }) catch |err| switch (err) {
        error.UnexpectedEof, error.EndOfStream => return error.TruncatedBzip2Data,
        error.OutputLimitExceeded => return error.FirmwareTooLarge,
        error.TrailingData => return error.TrailingBzip2Data,
        error.OutOfMemory => return error.Bzip2OutOfMemory,
        error.InvalidMagic,
        error.InvalidBlockSize,
        error.InvalidBlockHeader,
        error.InvalidFooter,
        error.CorruptData,
        error.HuffmanOverflow,
        error.InvalidSelector,
        error.BlockCrcMismatch,
        error.StreamCrcMismatch,
        error.OutputOverflow,
        error.InvalidBwtIndex,
        => return error.InvalidBzip2Data,
        else => return err,
    };
}
