# Third-Party Licenses

This document contains the licenses for third-party software components used by OMG.

## BSD-3-Clause Licensed Dependencies

The following cryptography dependencies use the BSD-3-Clause license:

### curve25519-dalek
Copyright (c) 2016-2021 Isis Agora Lovecruft, Henry de Valence. All rights reserved.

### ed25519-dalek
Copyright (c) 2017-2021 isis agora lovecruft. All rights reserved.

### x25519-dalek
Copyright (c) 2017-2021 isis agora lovecruft, Henry de Valence. All rights reserved.

### subtle
Copyright (c) 2016-2018 Isis Agora Lovecruft, Henry de Valence. All rights reserved.

### instant
Copyright (c) 2019 sebcrozet. All rights reserved.

**BSD-3-Clause License:**
```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## GPL-3.0 Licensed Dependencies (Optional Features)

### alpm & alpm-sys
**License:** GPL-3.0
**Feature:** `arch` (Arch Linux package manager integration)

Used for direct integration with libalpm (Arch Linux Package Manager).

---

## LGPL-2.0-or-later Licensed Dependencies (Optional Features)

### sequoia-openpgp
**License:** LGPL-2.0-or-later
**Feature:** `pgp` (PGP signature verification)

### buffered-reader
**License:** LGPL-2.0-or-later
**Dependency of:** sequoia-openpgp

OpenPGP implementation in Rust. Used as a library dependency without modification.

---

## ISC Licensed Dependencies

The following dependencies use the ISC license (functionally equivalent to MIT):

- **aws-lc-rs** - AWS cryptographic library for Rust
- **inotify** - Linux filesystem event monitoring
- **inotify-sys** - Low-level inotify bindings
- **rustls-webpki** - WebPKI X.509 certificate validation
- **untrusted** - Safe parsing of untrusted inputs

ISC License is very permissive and compatible with MIT.

---

## Runtime Dependencies (MIT/Apache-2.0)

The vast majority of Rust crates used are dual-licensed under MIT OR Apache-2.0:

**Core Dependencies:**
- **tokio** (MIT)
- **serde** (MIT OR Apache-2.0)
- **anyhow** (MIT OR Apache-2.0)
- **reqwest** (MIT OR Apache-2.0)
- **clap** (MIT OR Apache-2.0)
- **rayon** (MIT OR Apache-2.0)
- **redb** (MIT OR Apache-2.0)
- **tracing** (MIT)
- And 500+ others listed in Cargo.toml/Cargo.lock

For a complete list of all Rust dependencies and their licenses, run:
```bash
cargo tree --format "{p} {l}"
```

Or for a summary by license type:
```bash
cargo install cargo-license
cargo license
```

---

## bzip2-1.0.6 Licensed Dependency (Arch Feature)

### libbz2-rs-sys 0.2.6

The Rust bzip2 decoder is used through `bzip2` for Arch repository metadata.
Its license allowance is restricted to this package version in `deny.toml`.

[Upstream license](https://github.com/trifectatechfoundation/libbzip2-rs/blob/v0.2.6/COPYING)

```text

--------------------------------------------------------------------------

The original program, "bzip2", the associated library "libbzip2", and all
documentation, are

Copyright (C) 1996-2021 Julian R Seward.
Copyright (C) 2019-2020 Federico Mena Quintero
Copyright (C) 2021 Micah Snyder

This Rust translation, "libbzip2-rs" is a derived work based on "bzip2" and
"libbzip2", and is Copyright (C) 2024-2025 Trifecta Tech Foundation and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. The origin of this software must not be misrepresented; you must
   not claim that you wrote the original software.  If you use this
   software in a product, an acknowledgment in the product
   documentation would be appreciated but is not required.

3. Altered source versions must be plainly marked as such, and must
   not be misrepresented as being the original software.

4. The name of the author may not be used to endorse or promote
   products derived from this software without specific prior written
   permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Julian Seward, jseward@acm.org
bzip2/libbzip2 version 1.1.0 of 6 September 2010

--------------------------------------------------------------------------
```

---

## License Compatibility

OMG is licensed under the MIT License, which is compatible with:

| License | Compatible | Notes |
|---------|-----------|-------|
| MIT | ✅ Yes | Identical permissive license |
| Apache-2.0 | ✅ Yes | Permissive with patent grant |
| BSD-2-Clause | ✅ Yes | Permissive |
| BSD-3-Clause | ✅ Yes | Permissive with non-endorsement clause |
| ISC | ✅ Yes | Equivalent to MIT |
| Unlicense | ✅ Yes | Public domain equivalent |
| CC0-1.0 | ✅ Yes | Public domain |
| MPL-2.0 | ✅ Yes | File-level copyleft |
| LGPL-2.0+ | ✅ Yes | Library linking allowed |
| GPL-3.0 | ✅ Yes | Permitted in GPL binaries when optional features are compiled |

---

*Last Updated: September 2026*
