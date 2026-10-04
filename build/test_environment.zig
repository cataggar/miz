const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    var environ = try init.environ_map.clone(allocator);
    defer environ.deinit();
    var index: usize = 1;
    while (index < args.len and !std.mem.eql(u8, args[index], "--")) : (index += 2) {
        if (index + 1 >= args.len) return error.MissingEnvironmentValue;
        if (args[index].len == 0 or std.mem.indexOfScalar(u8, args[index], '=') != null)
            return error.InvalidEnvironmentName;
        try environ.put(args[index], args[index + 1]);
    }
    if (index >= args.len or index + 1 >= args.len) return error.MissingTestCommand;
    var child = try std.process.spawn(init.io, .{
        .argv = args[index + 1 ..],
        .environ_map = &environ,
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(init.io);
    std.process.exit(switch (term) {
        .exited => |code| code,
        .signal => |signal| @intCast(@min(255, 128 + @backingInt(signal))),
        else => return error.UnexpectedTestTermination,
    });
}
