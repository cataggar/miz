# Migration to miz

The rename from `vmiz` and the earlier `zvmi` name to `miz` is a hard breaking
cutover. There are no aliases, redirects, compatibility modules, environment
variable fallbacks, executable shims, schema translations, or path fallbacks.
Existing automation and stored identifiers must be migrated before using a
`miz` release.

## Repository, installation, and releases

- Change `https://github.com/cataggar/vmiz` repository URLs to
  `https://github.com/cataggar/miz`.
- Replace `ghr install cataggar/vmiz` with `ghr install cataggar/miz`; update
  scripts, caches, badges, issue links, and blob links to use `cataggar/miz`.
- Treat release assets as `miz` assets. Automation must not search the old
  repositories or executable names as a fallback.

## Commands, packages, and builds

- Replace every `vmiz` or `zvmi` CLI invocation with `miz`.
- Replace executable and helper names with `miz`, `mizinit`, `mizguest`,
  `miz-image-builder`, `miz-iso-builder`, and
  `miz-recustomize-iso-builder`.
- Update Zig dependency URLs and package names. Replace imports of `vmiz` or
  `zvmi` with `miz`, `vmiz_host` or `zvmi_host` with `miz_host`, and
  `vmiz-package-family-host` or `zvmi-package-family-host` with
  `miz-package-family-host`. The old module names are not registered.
- Update build steps, options, and artifact paths, including `mizguest`,
  `test-mizguest`, `test-mizinit`, `--mizinit`, `zig-out/bin/mizguest`, and
  `zig-out/bin/mizinit`.

## Configuration and boot contracts

- Rename every `VMIZ_*` environment variable to its `MIZ_*` equivalent.
  Unknown old variables are ignored rather than translated.
- Replace guest executable paths such as `/sbin/vmizinit` and
  `/usr/sbin/vmizinit` with `/sbin/mizinit` and `/usr/sbin/mizinit`.
  Replace `/usr/local/sbin/vmizinit-access` with
  `/usr/local/sbin/mizinit-access`, and replace every `vmizguest` path
  component with `mizguest`.
- Replace kernel options in the `vmizinit.*` namespace with `mizinit.*`,
  including `init=/sbin/mizinit`.
- Rename state and marker paths: `.vmiz/` to `.miz/`, `/etc/vmiz` to
  `/etc/miz`, `/run/vmiz-*` to `/run/miz-*`,
  `vmiz-local-provisioning` to `miz-local-provisioning`, and configuration
  filenames such as `vmiz.conf` to `miz.conf`.

## Serialized data and provenance

Serialized request, result, lock, state, marker, and provenance documents use
the `miz` schema and identifier names. Producers must emit the new identifiers,
and consumers must require them. Existing documents containing `vmiz` or
`zvmi` identifiers are not accepted or rewritten automatically; regenerate
them with `miz` or migrate them explicitly before use.
