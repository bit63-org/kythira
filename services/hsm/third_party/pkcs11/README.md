# OASIS PKCS#11 v3.0 headers

`pkcs11.h`, `pkcs11f.h` and `pkcs11t.h` are the OASIS PKCS #11 Cryptographic
Token Interface Base Specification Version 3.0 headers, copied unchanged from
the OASIS PKCS 11 TC's repository (`published/3-00/` in
<https://github.com/oasis-tcs/pkcs11>). They are vendored, not Kythira's work,
so they carry OASIS's notice and no Kythira header. `LICENSE.md` is that
repository's licence terms; each header's own notice says it is distributed
under the OASIS IPR Policy.

| File | SHA-256 |
|---|---|
| `pkcs11.h`  | `7cfb575ad695562407713c0426679707b2b9bbba3b6deff3b431e93a2bd62d3e` |
| `pkcs11f.h` | `11ee1d5026b1590a6c4a12be1023a2aec9ee185ba31bfb470084e4b6254779ee` |
| `pkcs11t.h` | `2a152db4d461e9a315428a3d037ff1ae896baa04af9d9409d696b3cbd4478c6c` |

Do not edit them. Kythira code includes them only through
`<kythira/hsm/pkcs11.hpp>`, which defines the five platform macros the
specification asks the includer to define. A newer version replaces all three
files at once and updates this table; `hsm_pkcs11_headers_test` checks the
version the headers declare.
