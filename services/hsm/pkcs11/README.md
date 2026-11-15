# libkythira_pkcs11.so

The PKCS#11 client library: what OpenSSL's pkcs11-provider, Go's crypto11,
Java's SunPKCS11 and `pkcs11-tool` load to reach the virtual HSM, over mutual
TLS or a Unix socket. It is its own target here, apart from the module's
headers, because it is shipped to hosts that run no Kythira node
(`.kiro/specs/virtual-hsm/` Requirement 1.2). It keeps no key material: every
call is one request on the wire (`wire_client.hpp`) to a node.

## Configuration

`KYTHIRA_PKCS11_CONF` names the file, read at `C_Initialize`. One setting per
line, `#` starts a comment:

```
socket    = /run/kythira/hsm.sock     # a node's Unix socket, tried first
endpoint  = hsm-1.example:9444        # a node's client listener; repeat,
endpoint  = hsm-2.example:9444, hsm-3.example:9444   # or comma separate
cert      = /etc/app/hsm-client.pem   # client certificate chain and key,
key       = /etc/app/hsm-client.key   # needed for any endpoint
ca        = /etc/app/hsm-ca.pem       # the CA the nodes' certificates chain to
timeout_s = 30                        # each read or write on the wire
```

Sockets come first, then endpoints, each in the order given. The node's
certificate must name the host dialled (an IP or DNS SAN). The identity the
node sees is the client certificate's first URI SAN, or the uid's entry in
the node's `KYTHIRA_HSM_SOCKET_ALLOW`. A file the library cannot read or
parse makes `C_Initialize` answer `CKR_GENERAL_ERROR` and print why on
stderr.

## Behaviour

- **Interfaces.** `C_GetInterface` and `C_GetInterfaceList` offer "PKCS 11"
  3.0 and 2.40; `C_GetFunctionList` returns the 2.40 list. These three are
  the only exported symbols (`kythira_pkcs11.map`); OpenSSL and the C++
  runtime's symbols stay local, so the library can be loaded into a process
  with its own OpenSSL, including OpenSSL itself through pkcs11-provider.
- **Slots.** One slot per token bound to the identity, numbered by token id.
  Slot info does not set `CKF_HW_SLOT`; token info names the manufacturer
  "Kythira" and the model "virtual HSM".
- **Threads.** One connection per process, since on the node one
  connection is one application and a login is the application's. Calls
  take one lock: the application's mutex callbacks when it passes them
  without `CKF_OS_LOCKING_OK`, a `std::mutex` otherwise.
- **Output lengths.** A null buffer or `CKR_BUFFER_TOO_SMALL` does not end
  the operation: the library keeps the node's output until a buffer large
  enough takes it, so the node runs the operation once. Multi-part
  encryption and decryption return everything at the final call.
- **Failover.** When an exchange fails the library connects to the next
  configured node that answers and restores each session with its flags,
  each slot's login (it keeps the PIN in this process for this), and each
  operation initialized with no data sent yet; the failed call is then tried
  once more. An operation that had sent data is lost: its next call answers
  `CKR_DEVICE_ERROR`. A session that made session objects is gone, since
  they lived on the old node: it answers `CKR_SESSION_HANDLE_INVALID`. With
  no node answering, calls answer `CKR_DEVICE_ERROR` until one does.
- **fork().** The child must call `C_Initialize` again; until then every
  call answers `CKR_CRYPTOKI_NOT_INITIALIZED`.
- **Not supported.** `C_GetOperationState`/`C_SetOperationState`, the
  recover and dual-function calls, `C_WaitForSlotEvent`, the 3.0 message
  functions and `C_LoginUser`/`C_SessionCancel` answer
  `CKR_FUNCTION_NOT_SUPPORTED`; `C_SeedRandom` answers
  `CKR_RANDOM_SEED_NOT_SUPPORTED`. `C_GetObjectSize` answers
  `CK_UNAVAILABLE_INFORMATION`.

## Building

`cmake --build build --target kythira_pkcs11` produces
`build/libkythira_pkcs11.so`. It links OpenSSL as the build finds it,
statically with vcpkg's default triplets; with a shared system OpenSSL the
library depends on that `libcrypto`/`libssl` instead. It is linked
`-z nodelete`, so a `dlclose` leaves it mapped and OpenSSL's exit handlers
inside it stay valid.

`hsm_pkcs11_library_test` loads it with `dlopen` against wire servers on
Unix sockets; the consumer tests (pkcs11-tool, pkcs11-provider, p11-kit,
pkcs11test, Go, Java) are task 10b.
