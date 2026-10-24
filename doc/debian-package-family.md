# Ubuntu and Debian package-family integration

`miz.package_family` selects package behavior without changing the existing
RPM customization backend. Azure Linux continues through that backend.
Host-side Ubuntu 26.04 and Debian requests call the embedded debz Zig API
directly through its native transaction backend (`transaction_backend = .native`,
`invokes_apt = false`, `invokes_dpkg = false`); the default path does not spawn
`debz`, `dpkg`, `apt`, or `apt-get` and does not use libapt-pkg or python-apt.
Static init, guest, and cross-target modules
do not import or link debz. Build consumers that need this API use the
host-targeted `miz_host` module; the cross-target `miz` module stays free of
host package-manager linkage. These are the only supported module names; the
cutover does not provide compatibility aliases. The public modules link miz's
pinned static
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
debz package-family schema v2 accepts zero or one package depending on the
operation. miz exposes a package list but rejects more than one name with a
typed diagnostic rather than silently dropping names.

The immutable Zig dependency is debz 0.4.0 at commit
`a6c2732e2cab880b60a4affadb7e087bf007d1e8` (hash
`debz-0.4.0-Mmw8sO5pXwOV9_QmGQlZGVN0EydN0r0GhdT1MWNf0MUc`). At every call
boundary miz checks the debz capability
(`io.github.cataggar.debz.package-family.capabilities.v2`), request
(`io.github.cataggar.debz.package-family.request.v2`), and result
(`io.github.cataggar.debz.package-family.result.v2`) schemas at version `2`,
the native transaction backend (`transaction_backend = .native`,
`invokes_apt = false`, `invokes_dpkg = false`), the exact-lock schema
(`https://debz.dev/schema/exact-closure-lock-v3`, version `3`), and the
provenance schema (`https://debz.dev/schema/native-transaction-provenance-v2`,
version `2`) before accepting output.

For create/customize/update, debz runs against `root_stage`. miz parses the
canonical exact-lock document (`https://debz.dev/schema/exact-closure-lock-v3`,
version `3`), checks its target architecture, validates the native transaction
provenance (`https://debz.dev/schema/native-transaction-provenance-v2`, version
`2`) digest and `exact_lock_sha256` binding, stages the verified provenance
from `{root_stage}/var/lib/debz/native-transaction-provenance-v2.json` to
`{state_path}/transaction-result.json`, and cleans up `{root_stage}/var/lib/debz`
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
