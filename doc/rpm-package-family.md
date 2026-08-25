# Host RPM package-family integration

The public host adapter is the Zig module `miz-package-family-host`. It uses
only the supported `@import("rpmz")` namespaces: `resolver` for deterministic
planning, `bundle_export` for the closed input set, and `replay` for exact
offline execution. rpmz is pinned to immutable commit
`15b5e1291a9fc3eb3980a4088d757b9d0254d468`. The dependency key used by a
consumer is irrelevant, so a future repository rename does not change the
module API.

RPM requests default to `.rpmz`. The existing in-target `/usr/bin/tdnf` and
`/usr/bin/rpm` callback is selected only with `.legacy_tdnf`; an rpmz error is
returned and is never retried through the legacy backend.

`RpmOptions` declares the complete repository set, local snapshots or remote
base URLs, explicit key paths and signature policy, distro, release, target
architecture, staged install root, rpmdb path, cache, scratch directory,
package action, exact package locks, and bundle input/output. No root or host
repository configuration is consulted by rpmz. Credentials in URLs are
rejected by its public resolver.

For a new transaction, the adapter exports a replay-capable v2 bundle and then
replays that exact bundle against `root_stage`. For an existing lock,
`bundle_input_path` bypasses planning and performs exact offline replay.
Publication occurs only after rpmz reports success, an applied plan digest,
and a verified final inventory satisfying miz's exact locks. The adapter
writes versioned miz lock and provenance documents before atomically renaming
the staged root to `published_root`.

Target trust import, recovery, inspection, and multi-transaction bundles are
not operations exposed by rpmz public replay. Requests for them return
`unsupported_operation`; they never report synthetic success. RPM payload
scriptlets remain untrusted, so callers requiring network isolation must
enforce it at the OS boundary.
