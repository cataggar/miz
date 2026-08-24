# Ubuntu and Debian package-family integration

`vmiz.package_family` selects package behavior without changing the existing
RPM customization backend. Azure Linux continues through that backend.
Host-side Ubuntu 26.04 and Debian requests call the embedded debz Zig API
directly; the default path does not spawn `debz`, `apt`, or `apt-get` and does
not use libapt-pkg or python-apt. Static init, guest, and cross-target modules
do not import or link debz. Build consumers that need this API use the
host-targeted `vmiz_host` module; the cross-target `vmiz` module stays free of
host package-manager linkage. The pre-rename `zvmi` and `zvmi_host` module
names remain compatibility aliases over the same sources, while new consumers
should use `vmiz` and `vmiz_host`. The public modules link vmiz's pinned static
libzstd dependency. Package-family consumers additionally pick up debz's
liblzma/libzstd dependencies through its Zig build module.

The version 3 request makes the staged and published root, native/foreign
architectures, repository sources, keyrings, configuration, cache, state,
credential reference, exact lock, and network policy explicit. `offline`
becomes debz cache-only mode. Credentials remain indirect references and are
never copied into diagnostics or artifacts. Repository priority, conffile,
recommendation, downgrade, deadline, and lock-wait policies are typed fields.

The operation sequence is `resolve_lock`, human or policy review of the exact
lock, then locked `create`, `customize`, `update`, `recover`, or `inspect`.
debz package-family schema v1 accepts zero or one package depending on the
operation. vmiz exposes a package list but rejects more than one name with a
typed diagnostic rather than silently dropping names.

The immutable Zig dependency is debz commit
`beac3f20dd93fd98863af71e8fe621d47db663f6`. At every call boundary vmiz checks
the debz capability, request, result, exact-lock, and provenance schemas before
accepting output.

For create/customize/update, debz runs against `root_stage`. vmiz parses the
canonical exact-lock document, checks its target architecture, validates the
provenance digest and lock binding, and verifies `state/transaction-result.json`
before an atomic
rename-without-replacement publishes `published_root`. Backend, verification,
or publication failures return typed diagnostics with a disposable or
recoverable disposition and never report or publish success. Download and
planning failures delete the disposable stage; dpkg/recovery and publication
failures retain recoverable state.

Callers resolving against a preinstalled root can require a locked installed
baseline. debz then imports every fully installed dpkg identity, binds unchanged
packages to authenticated repository records as retained entries, and refuses
missing packages, version drift, or architecture drift.

Hermetic tests inject a typed debz product executor and cover an Ubuntu
26.04-style resolve/review/create fixture, amd64 and arm64/foreign selection,
offline lock replay, capability and provenance gating, credential-redacted
backend failure, cleanup, and no-partial-publication behavior. The external
build consumer also compiles the public package-family API.
