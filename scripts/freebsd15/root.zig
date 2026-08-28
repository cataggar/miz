//! The FreeBSD 15.1 release tooling, replacing `scripts/freebsd15_release.py`
//! and `scripts/freebsd15_azure_metadata.py`.
//!
//! Import this aggregate rather than the individual files so a caller picks up
//! the whole contract set:
//!
//! * `profiles` — the pinned variant, package, release-set, and contract tables
//! * `document` — strict JSON accessors and the shared failure `Context`
//! * `candidate` — recorded manifests, candidate validation, result documents
//! * `staging` — full/core pairing, the size gate, staging, and release notes
//! * `publication` — the staged and published allowlists the shell enforces
//! * `azure_metadata` — Azure resource metadata validation for the harness

pub const cli = @import("cli.zig");
pub const profiles = @import("profiles.zig");
pub const document = @import("document.zig");
pub const candidate = @import("candidate.zig");
pub const staging = @import("staging.zig");
pub const publication = @import("publication.zig");
pub const azure_metadata = @import("azure_metadata.zig");

pub const Context = document.Context;
pub const Error = document.Error;

test {
    _ = cli;
    _ = profiles;
    _ = document;
    _ = candidate;
    _ = staging;
    _ = publication;
    _ = azure_metadata;
}
