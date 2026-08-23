# Third-Party Notices

## rpmz

The host-only RPM package-family adapter uses `cataggar/rpmz` at immutable
commit `15b5e1291a9fc3eb3980a4088d757b9d0254d468`. rpmz is not imported by the
guest agent or init static modules.

Copyright (c) rpmz contributors.

rpmz library source is licensed under LGPL-2.1 and utility source under
GPL-2.0. See:
https://github.com/cataggar/rpmz/blob/15b5e1291a9fc3eb3980a4088d757b9d0254d468/COPYING

## ghr Authenticode parser

`packages/vmiz/src/authenticode.zig` adapts PE parsing and Authenticode
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

Host/public vmiz module graphs link `cataggar/zstd` from its Zig 0.16 branch
at immutable commit `45b6dfcd9d0ffdba99fb653c66b233179b9f7229` as a static,
single-threaded library (`tools=false`, `shared=false`, `multithread=false`).
Private guest-root builds reuse only the public headers and do not link the
library or libc.

Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

Licensed under the BSD License for Zstandard software. See:
https://github.com/cataggar/zstd/blob/45b6dfcd9d0ffdba99fb653c66b233179b9f7229/LICENSE

The upstream CLI utility sources are GPL-2.0 (`COPYING`), but this repository
does not build them because the dependency is configured with `tools=false`.

## tls.zig (test fixture only)

The deterministic OCI registry TLS fixture uses `cataggar/tls.zig` at commit
`2621e411af81c8b4d8fa5aaae08b9b183a80bb46` from its Zig 0.16 branch. It is
not linked into the library or CLI.

Copyright (c) tls.zig contributors.

Licensed under the MIT License. See:
https://github.com/cataggar/tls.zig/blob/2621e411af81c8b4d8fa5aaae08b9b183a80bb46/LICENSE

## debz

Host-side Debian-family package operations embed `cataggar/debz` at immutable
commit `beac3f20dd93fd98863af71e8fe621d47db663f6`.

Copyright (c) debz contributors.

Licensed under the Apache License 2.0. See:
https://github.com/cataggar/debz/blob/beac3f20dd93fd98863af71e8fe621d47db663f6/LICENSE

debz links its statically configured Debian-semantics libsolv dependency and
system libc, liblzma, and libzstd through its Zig package build conventions.
See debz's notices for the corresponding BSD-3-Clause and 0BSD terms:
https://github.com/cataggar/debz/blob/beac3f20dd93fd98863af71e8fe621d47db663f6/THIRD_PARTY_NOTICES
