# Third-Party Notices

## ghr Authenticode parser

`packages/vmiz/src/authenticode.zig` adapts PE parsing and Authenticode
range-hashing code from ghr.

Copyright (c) 2026 Cameron Taggart.

Licensed under the MIT License. See:
https://github.com/ctaggart/ghr/blob/main/LICENSE

## zig-bzip2

This project vendors the `silver-signal/zig-bzip2` Zig build wrapper, version
1.0.8.

Copyright (c) 2024 silver-signal contributors.

Licensed under the MIT License. See:
https://github.com/silver-signal/zig-bzip2/blob/1.0.8/LICENSE

## tls.zig (test fixture only)

The deterministic OCI registry TLS fixture uses `cataggar/tls.zig` at commit
`2621e411af81c8b4d8fa5aaae08b9b183a80bb46` from its Zig 0.16 branch. It is
not linked into the library or CLI.

Copyright (c) tls.zig contributors.

Licensed under the MIT License. See:
https://github.com/cataggar/tls.zig/blob/2621e411af81c8b4d8fa5aaae08b9b183a80bb46/LICENSE

## bzip2

This project statically links bzip2 version 1.0.8.

Copyright (c) 1996-2019 Julian R Seward.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the conditions in the bzip2 1.0.8
license are met. See:
https://sourceware.org/bzip2/1.0.8/LICENSE

## debz

Host-side Debian-family package operations embed `cataggar/debz` at immutable
commit `d5385857a44fca753af515e805af70be9f004183`.

Copyright (c) debz contributors.

Licensed under the Apache License 2.0. See:
https://github.com/cataggar/debz/blob/d5385857a44fca753af515e805af70be9f004183/LICENSE

debz links its statically configured Debian-semantics libsolv dependency and
system libc, liblzma, and libzstd through its Zig package build conventions.
See debz's notices for the corresponding BSD-3-Clause and 0BSD terms:
https://github.com/cataggar/debz/blob/d5385857a44fca753af515e805af70be9f004183/THIRD_PARTY_NOTICES
