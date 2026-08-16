# Ubuntu and Debian package-family integration

`zvmi.package_family` selects package behavior without changing the existing
RPM customization backend. Azure Linux continues through that backend;
Ubuntu 26.04 and Debian requests are delegated only to the public debz CLI/API.
zvmi never invokes `apt`, `apt-get`, libapt-pkg, or python-apt.

The version 1 request makes the staged and published root, native/foreign
architectures, repository sources, keyrings, configuration, cache, state,
credential reference, exact lock, and network policy explicit. `offline`
becomes debz cache-only mode. Credentials remain indirect references and are
never copied into diagnostics or artifacts.

For create/customize/update, debz runs against `root_stage`. zvmi verifies the
exact lock and `state/transaction-result.json` before an atomic
rename-without-replacement publishes `published_root`. Backend, verification,
or publication failures return typed diagnostics with a disposable or
recoverable disposition and never report or publish success. Download and
planning failures delete the disposable stage; dpkg/recovery and publication
failures retain recoverable state.

Hermetic tests cover Ubuntu 26.04-style initial roots, amd64 and arm64/foreign
selection, offline lock replay, provenance gating, backend failure, cleanup,
and no-partial-publication behavior. Real snapshot testing is optional because
it requires retained immutable Ubuntu snapshots and the Ubuntu archive
keyring; it supplements rather than replaces the deterministic fixture lane.
