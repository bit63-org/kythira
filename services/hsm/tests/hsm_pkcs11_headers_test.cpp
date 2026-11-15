// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// The vendored OASIS PKCS#11 v3.0 headers (services/hsm/third_party/pkcs11/)
// through <kythira/hsm/pkcs11.hpp>: they compile as C++23 under the platform
// macros that header defines, declare version 3.0, and carry the pieces of
// the 3.0 interface libkythira_pkcs11.so will export (task 10). A header
// swapped for another version, or a macro definition that breaks the
// function table's layout, fails here before anything links against it.

#define BOOST_TEST_MODULE hsm_pkcs11_headers_test
#include <boost/test/unit_test.hpp>

#include <kythira/hsm/pkcs11.hpp>

#include <cstddef>
#include <cstring>
#include <type_traits>

BOOST_AUTO_TEST_CASE(headers_declare_version_3_0) {
    BOOST_TEST(CRYPTOKI_VERSION_MAJOR == 3);
    BOOST_TEST(CRYPTOKI_VERSION_MINOR == 0);
    BOOST_TEST(kythira::hsm::cryptoki_version.major == 3);
    BOOST_TEST(kythira::hsm::cryptoki_version.minor == 0);
}

BOOST_AUTO_TEST_CASE(platform_types_match_the_unix_abi) {
    // CK_ULONG is `unsigned long` on every Unix ABI the consumers use
    // (OpenSSL's pkcs11-provider, Go's crypto11, Java's SunPKCS11), so a
    // mismatch would corrupt every call across the dlopen boundary.
    static_assert(std::is_same_v<CK_ULONG, unsigned long>);
    static_assert(std::is_same_v<CK_BYTE, unsigned char>);
    static_assert(std::is_same_v<CK_BYTE_PTR, CK_BYTE*>);
    static_assert(std::is_pointer_v<CK_C_GetFunctionList>);
    BOOST_TEST(sizeof(CK_ULONG) == sizeof(void*));
}

BOOST_AUTO_TEST_CASE(function_list_3_0_has_the_new_entry_points) {
    // CK_FUNCTION_LIST_3_0 is CK_FUNCTION_LIST plus the 3.0 calls, in order:
    // its first member after the version is C_Initialize, and C_LoginUser,
    // C_SessionCancel and C_MessageEncryptInit follow the 2.40 table.
    static_assert(offsetof(CK_FUNCTION_LIST_3_0, version) == 0);
    static_assert(offsetof(CK_FUNCTION_LIST_3_0, C_Initialize) ==
                  offsetof(CK_FUNCTION_LIST, C_Initialize));
    static_assert(offsetof(CK_FUNCTION_LIST_3_0, C_WaitForSlotEvent) ==
                  offsetof(CK_FUNCTION_LIST, C_WaitForSlotEvent));
    static_assert(offsetof(CK_FUNCTION_LIST_3_0, C_GetInterfaceList) >
                  offsetof(CK_FUNCTION_LIST_3_0, C_WaitForSlotEvent));
    static_assert(offsetof(CK_FUNCTION_LIST_3_0, C_LoginUser) >
                  offsetof(CK_FUNCTION_LIST_3_0, C_GetInterfaceList));
    static_assert(offsetof(CK_FUNCTION_LIST_3_0, C_MessageEncryptInit) >
                  offsetof(CK_FUNCTION_LIST_3_0, C_SessionCancel));
    BOOST_TEST(sizeof(CK_FUNCTION_LIST_3_0) > sizeof(CK_FUNCTION_LIST));
}

BOOST_AUTO_TEST_CASE(constants_the_module_relies_on) {
    // Values fixed by the specification; a swapped or edited header shows
    // up as a changed constant.
    BOOST_TEST(CKR_OK == 0UL);
    BOOST_TEST(CKR_FUNCTION_NOT_SUPPORTED == 0x54UL);
    BOOST_TEST(CKR_MECHANISM_INVALID == 0x70UL);
    BOOST_TEST(CKM_AES_GCM == 0x1087UL);
    BOOST_TEST(CKM_AES_KEY_WRAP_KWP == 0x210BUL);
    BOOST_TEST(CKM_ECDSA == 0x1041UL);
    BOOST_TEST(CKM_RSA_PKCS_PSS == 0x0DUL);
    BOOST_TEST(CKA_SENSITIVE == 0x103UL);
    BOOST_TEST(CKA_EXTRACTABLE == 0x162UL);
    BOOST_TEST(CKU_SO == 0UL);
    BOOST_TEST(CKU_USER == 1UL);
}

BOOST_AUTO_TEST_CASE(interface_struct_names_pkcs11) {
    // C_GetInterface hands out CK_INTERFACE{"PKCS 11", &list, flags}; the
    // struct holds a name pointer, the list pointer and the flags.
    char name[] = "PKCS 11";
    CK_FUNCTION_LIST_3_0 list{};
    list.version = kythira::hsm::cryptoki_version;
    const CK_INTERFACE iface{reinterpret_cast<CK_CHAR*>(name), &list, 0};
    BOOST_TEST(std::strcmp(reinterpret_cast<const char*>(iface.pInterfaceName), "PKCS 11") == 0);
    BOOST_TEST(static_cast<const CK_FUNCTION_LIST_3_0*>(iface.pFunctionList)->version.major == 3);
}
