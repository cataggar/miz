//! `freebsd15_azure_metadata`: validate the Azure metadata the FreeBSD 15.1
//! acceptance harness acts on.
//!
//! Native port of `scripts/freebsd15_azure_metadata.py` plus the inline Python
//! the harness used to embed. Each subcommand takes the same positional
//! arguments as the Python it replaces, prints the same evidence on success,
//! and prints the same single failure line and exit code on rejection.

const std = @import("std");
const freebsd15 = @import("freebsd15");

pub fn main(init: std.process.Init) !void {
    return freebsd15.cli.runAzureMetadata(init);
}
