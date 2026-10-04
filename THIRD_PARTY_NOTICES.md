# Third-Party Notices

## translate-c (build tool)

Zig 0.17 C-header bindings use `cataggar/translate-c` at immutable commit
`62d06a5d3e93c82727544e8113e4762a315ca0ed`. This is the reviewed compiler
compatibility revision; it is a build tool, not an additional runtime library.

Copyright (c) Zig contributors.

Licensed under the MIT License (Expat). See:
https://github.com/cataggar/translate-c/blob/62d06a5d3e93c82727544e8113e4762a315ca0ed/LICENSE

The tool uses the Aro C frontend from `cataggar/arocc` at immutable commit
`d0c8c4d9c55daa7ef6e40cf0f630a5b5e900989b`.

Copyright (c) 2021 Veikka Tuominen.

Licensed under the MIT License. See:
https://github.com/cataggar/arocc/blob/d0c8c4d9c55daa7ef6e40cf0f630a5b5e900989b/LICENSE

## rpmz

The host-only RPM package-family adapter uses `cataggar/rpmz` at immutable
commit `15b5e1291a9fc3eb3980a4088d757b9d0254d468`. rpmz is not imported by the
guest agent or init static modules.

Copyright (c) rpmz contributors.

rpmz library source is licensed under LGPL-2.1 and utility source under
GPL-2.0. See:
https://github.com/cataggar/rpmz/blob/15b5e1291a9fc3eb3980a4088d757b9d0254d468/COPYING

## ghr Authenticode parser

`packages/miz/src/authenticode.zig` adapts PE parsing and Authenticode
range-hashing code from ghr.

Copyright (c) 2026 Cameron Taggart.

Licensed under the MIT License. See:
https://github.com/ctaggart/ghr/blob/main/LICENSE

## bzip2z

Host-side firmware decompression uses `cataggar/bzip2z` at immutable commit
`05f6d4e34df2da2729490aee2a5bbe43b5ce94f6`.

Copyright (c) 2026 Peter Marreck.

Licensed under the MIT License. See:
https://github.com/cataggar/bzip2z/blob/05f6d4e34df2da2729490aee2a5bbe43b5ce94f6/LICENSE

## zstd

Host/public miz module graphs link `cataggar/zstd` at immutable commit
`71502da18ccdacac0c2049c033dedbbf25a40b93` as a static,
single-threaded library (`tools=false`, `shared=false`, `multithread=false`).
Private guest-root builds reuse only the public headers and do not link the
library or libc.

Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

Licensed under the BSD License for Zstandard software. See:
https://github.com/cataggar/zstd/blob/71502da18ccdacac0c2049c033dedbbf25a40b93/LICENSE

The upstream CLI utility sources are GPL-2.0 (`COPYING`), but this repository
does not build them because the dependency is configured with `tools=false`.

## tls.zig (test fixture only)

The deterministic OCI registry TLS fixture uses `cataggar/tls.zig` at commit
`481b2a677244b994d216eb02a73bad89623610a9`. It is
not linked into the library or CLI.

Copyright (c) tls.zig contributors.

Licensed under the MIT License. See:
https://github.com/cataggar/tls.zig/blob/481b2a677244b994d216eb02a73bad89623610a9/LICENSE

## debz

Host-side Debian-family package operations embed `cataggar/debz` at immutable
commit `56be0a32fac5293f20bde45d266b708e53321c73`.

Copyright (c) debz contributors.

Licensed under the Apache License 2.0. See:
https://github.com/cataggar/debz/blob/56be0a32fac5293f20bde45d266b708e53321c73/LICENSE

debz links its statically configured Debian-semantics libsolv dependency and
static liblzma and libzstd, together with libc, through its Zig package build
conventions.
See debz's notices for the corresponding BSD-3-Clause and 0BSD terms:
https://github.com/cataggar/debz/blob/56be0a32fac5293f20bde45d266b708e53321c73/THIRD_PARTY_NOTICES

## zerde (transitive dependency)

The zlua transitive package graph uses `cataggar/zerde` at immutable commit
`48d215aab4d351c199dd4f164c2926f433c7f296`. It is not a direct root dependency.

Package URL:
`git+https://github.com/cataggar/zerde#48d215aab4d351c199dd4f164c2926f433c7f296`

Zig package hash:
`zerde-0.3.1-r7zGa1fnDABoOl0E1S4iXOE4C-sBPoqG7kkJYszzvRiB`

Copyright (c) 2026 Grant Wade.

Licensed under the MIT License. See:
https://github.com/cataggar/zerde/blob/48d215aab4d351c199dd4f164c2926f433c7f296/LICENSE
