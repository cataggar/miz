//! `freebsd15_release`: validate, stage, and publish FreeBSD 15.1 release
//! artifacts.
//!
//! Native port of `scripts/freebsd15_release.py`. The subcommands the release
//! workflow, the staging script, the publisher, and the Azure acceptance
//! harness call are unchanged; the implementation lives in the `freebsd15`
//! module so the contract tests can exercise it without a subprocess.

const std = @import("std");
const freebsd15 = @import("freebsd15");

pub fn main(init: std.process.Init) !void {
    return freebsd15.cli.runRelease(init);
}
