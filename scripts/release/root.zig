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
pub const github_release = @import("github_release.zig");
pub const azure_vhd_layout = @import("azure_vhd_layout.zig");
pub const azure_compute = @import("azure_compute.zig");
pub const azure_confidential_vm = @import("azure_confidential_vm.zig");
pub const azure_trusted_launch = @import("azure_trusted_launch.zig");

pub const Diagnostic = contract.Diagnostic;

test {
    _ = contract;
    _ = file;
    _ = digest;
    _ = json_document;
    _ = github_release;
    _ = azure_vhd_layout;
    _ = azure_compute;
    _ = azure_confidential_vm;
    _ = azure_trusted_launch;
}
