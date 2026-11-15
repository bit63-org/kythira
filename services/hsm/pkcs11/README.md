# libkythira_pkcs11.so

The PKCS#11 client library: what OpenSSL's pkcs11-provider, Go's crypto11,
Java's SunPKCS11 and `pkcs11-tool` load to reach the virtual HSM, over mutual
TLS or a Unix socket. It is its own target here, apart from the module's
headers, because it is shipped to hosts that run no Kythira node
(`.kiro/specs/virtual-hsm/` Requirement 1.2). It arrives in task 10.
