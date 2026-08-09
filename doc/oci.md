# OCI images and bundles

`zvmi oci` copies, inspects, unpacks, and repacks OCI images without a
container daemon:

```console
zvmi oci copy docker://registry.example/team/image:stable oci:./layout:stable
zvmi oci copy --override-os linux --override-arch arm64 oci:./layout:stable docker://registry.example/team/image:arm64
zvmi oci copy --all docker://registry.example/team/image:stable oci:./complete:stable
zvmi oci inspect oci:./layout:stable
zvmi oci list-tags docker://registry.example/team/image
zvmi oci unpack --image oci:./layout:stable ./bundle
zvmi oci repack --image oci:./layout:edited ./bundle
zvmi oci config --image oci:./layout:edited
```

`copy`, `unpack`, and `repack` print the committed or selected root digest.
`inspect`, `list-tags`, and `config` print JSON. Diagnostics are written to
stderr.

## References

Registry references are explicit: `docker://host[:port]/repository:tag` or `docker://host[:port]/repository@sha256:<hex>`. Copy and inspect require a tag or digest; list-tags requires a repository with neither. There is no implicit Docker Hub, `latest`, or unqualified-name search.

Local references are `oci:<path>[:name]` or `oci:<path>@sha256:<hex>`. A source without a selector is accepted only when `index.json` has one unambiguous descriptor. A name is the top-level `org.opencontainers.image.ref.name` annotation. A destination without a name creates an unannotated root descriptor.

Only SHA-256 is supported. User information, query strings, fragments, uppercase registry repository components, malformed digests, and unsafe digest-derived paths are rejected.

## Platform selection

Copy and inspect select the host OCI platform by default. Use `--override-os`, `--override-arch`, and `--override-variant` to select another platform. OCI architecture names such as `amd64` and `arm64` are required. Explicit overrides also validate the config platform of a single-manifest image.

`--all` is mutually exclusive with overrides and preserves the complete recursive index graph. Selected-platform mode publishes the matched leaf manifest as the destination root and does not download unrelated platforms. Nested indexes are bounded and cycle checked. Unknown index children are preserved as verified opaque content in `--all` mode.

OCI manifests/indexes and Docker schema-2 manifests/lists are supported. Docker schema 1 is not.

## Exact content and publication

Manifest and index bytes are hashed and copied exactly; publication never reserializes them. Configs, layers, and metadata are verified against descriptor size and SHA-256 while streaming. Existing destination blobs are reused only after verification.

Local layouts publish `index.json` last under an advisory lock. Existing names and unknown descriptor fields are preserved, while replacing a name changes only that reference. An interruption may leave verified unreferenced blobs, but it does not expose a partial new reference.

Registry destinations check for existing blobs, attempt a cross-repository mount for same-registry copies, upload missing content, and publish manifests dependency-first. The destination tag or digest is committed by the final manifest PUT. A failed operation may leave unreferenced blobs or abandoned upload sessions for registry garbage collection.

## Editable runtime bundles

`unpack` accepts a local OCI-layout reference through `--image` and creates an
OCI runtime bundle containing `rootfs/` and `config.json`. It resolves nested
indexes for the host platform by default; `--override-os`, `--override-arch`,
and `--override-variant` select another platform. Compressed descriptor size
and SHA-256, the uncompressed DiffID, tar checksums, paths, PAX metadata, entry
sizes, entry count, and total expanded bytes are all verified or bounded.

Extraction applies layers in order and implements regular and opaque
whiteouts. Archive-controlled symlinks are never followed while creating
parents. Regular files, directories, symlinks, hard links, modes, nanosecond
timestamps, ownership, FIFOs, Linux device nodes, and `user.`, `trusted.`,
`security.`, and `system.` PAX xattrs are preserved. Device creation and
privileged ownership/xattrs require the corresponding Linux capabilities.
Symlink xattrs are rejected rather than silently discarded.

Image `Entrypoint` and `Cmd` become runtime arguments, with `/bin/sh` as the
empty-command fallback. Environment, working directory, numeric or named
users, supplemental groups, volumes, exposed ports, stop signal, labels, and
standard image annotations are translated. Named users and groups are
resolved from the extracted `/etc/passwd` and `/etc/group`; malformed or
missing requested entries fail unpack.

The destination must not exist unless `--force` is supplied. A new bundle is
built in a same-parent staging directory and renamed only after all content,
`config.json`, the base snapshot, and provenance are synced. On Linux,
`--force` uses `renameat2(RENAME_EXCHANGE)`; there is no non-atomic fallback.
An extraction or verification failure leaves the existing bundle visible.

`--rootless` stores all extracted objects under the invoking UID/GID while
recording the image UID/GID for every base path. The runtime configuration
maps container ID 0 to that host UID/GID. Repack restores recorded ownership
for base paths and maps new paths owned by the invoking UID/GID to container
ID 0; any other new ownership is rejected as unmapped. This one-ID mapping
does not emulate a subordinate-ID range, so rootless unpack rejects images
configured to run as a nonzero user or with supplemental groups.

The private `.zvmi/metadata.json` records the exact root and selected manifest,
config digest, platform, source layout, and unpack ownership mode.
`.zvmi/base.json` is a sorted, no-follow snapshot containing content hashes,
links, modes, timestamps, owners, device numbers, and base64 xattrs. Repack
refuses a missing or changed base graph.

`repack` compares `rootfs/` with that snapshot, emits deterministic additions,
metadata/content changes, hard links, and whiteouts, and appends one history
entry and DiffID. The layer tar is ordered, PAX metadata is canonical, and
gzip output is reproducible. `--compression same` (the default) preserves
uncompressed or gzip layer compression and the OCI/Docker media-type family;
`--compression gzip` and `--compression none` override it. Repacking a zstd
base with `same` is rejected because zstd layer encoding is not currently
implemented.

Config, layer, manifest, and ancestor-index blobs are written
content-addressably. The destination name is changed by a final locked
`index.json` replacement, so a new tag leaves the source tag unchanged.
Verified unreferenced blobs may remain after interruption and are safe for
layout garbage collection.

`config --image ...` resolves the same selected image and prints its verified
image-configuration JSON without rewriting extension fields.

## Registry options and authentication

HTTPS with system trust and hostname verification is the default. `--tls-ca <pem>` adds certificates to system trust. There is no certificate-verification bypass. `--plain-http` is intended for development registries; credentials and bearer tokens are rejected over non-loopback HTTP.

Copy has separate `--src-authfile`, `--src-tls-ca`, `--src-plain-http`, `--dest-authfile`, `--dest-tls-ca`, and `--dest-plain-http` options. Inspect and list-tags use `--authfile`, `--tls-ca`, and `--plain-http`. Supplying registry options for a local layout is an error.

Credential lookup order is:

1. Explicit auth file
2. `REGISTRY_AUTH_FILE`
3. `${XDG_RUNTIME_DIR}/containers/auth.json`
4. `${XDG_CONFIG_HOME}/containers/auth.json` (or `$HOME/.config/containers/auth.json`)
5. `$HOME/.docker/config.json`
6. `$HOME/.dockercfg`

That order applies whenever a credential is discovered. A library caller may
instead state one directly through `registry.Options.credential`, which
disables discovery entirely: none of the six locations above, and no credential
helper they name, is consulted. A registry that needs authentication then fails
as an authentication error naming the reference rather than succeeding because
the machine happened to be logged in. The `zvmi oci` commands do not state a
credential and keep the discovery behaviour above.

The client supports `auths`, per-registry `credHelpers`, global `credsStore`, Basic challenges, and Bearer token challenges. The `auth` field is Base64 encoding, not encryption. Credential helpers receive the registry key on stdin, never as a command argument. Credentials, bearer tokens, challenge values, and signed upload URLs are not included in diagnostics.

Responses use identity encoding. Metadata is bounded to 16 MiB, response headers to 64 KiB, and blob streaming uses a 64 KiB buffer. GET and HEAD requests make at most three attempts for transient connection/status failures, with bounded `Retry-After` handling, and follow at most five redirects. HTTPS downgrade is rejected. Registry authorization is stripped from cross-origin blob and signed HTTPS upload requests; token redirects cannot cross origin.

## JSON output

Inspect output has `schema_version`, `reference`, `media_type`, `digest`, `size`, `kind`, `annotations`, `platform`, `config`, `layers`, and `manifests`. Descriptors include media type, digest, size, annotations, and platform where applicable. Selected-platform inspection returns a manifest; `--all` returns the recursive index graph.

Tag output has `schema_version`, `repository`, and a deduplicated, lexically sorted `tags` array. Pagination is automatic and bounded.

## Current limits

The OCI commands do not support schema 1, non-SHA-256 digests,
referrers/signatures, trust policies, insecure HTTPS, proxies, mTLS, resumable
cross-process uploads, registry catalogs/deletion, or non-OCI transports.
Bundle operations currently require local layouts. Repack does not encode
zstd layers or preserve symlink xattrs.
