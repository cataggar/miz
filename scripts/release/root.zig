//! Shared foundation for the Zig release tooling that is replacing this
//! repository's Python release scripts.
//!
//! Import this aggregate rather than the individual files so a caller picks up
//! the whole contract set:
//!
//! * `contract` — failure diagnostics, digest/commit shapes, MiB rendering
//! * `file` — bounded reads, file identity, atomic output staging
//! * `digest` — streaming SHA-256 over bounded files
//! * `json_document` — strict document reads and canonical document writes

pub const contract = @import("contract.zig");
pub const file = @import("file.zig");
pub const digest = @import("digest.zig");
pub const json_document = @import("json_document.zig");
pub const azure_vhd_layout = @import("azure_vhd_layout.zig");
/// Test-only support. Exposed so a consumer that imports this module by name
/// can reach `TempTree` without pulling the same file into a second module.
pub const testing = @import("testing.zig");

pub const Diagnostic = contract.Diagnostic;

test {
    _ = contract;
    _ = file;
    _ = digest;
    _ = json_document;
    _ = azure_vhd_layout;
}
