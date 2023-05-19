#pragma once

#include "electronic-id/electronic-id.hpp"

#include "scope.hpp"

#include <openssl/x509v3.h>
#include <openssl/err.h>

namespace electronic_id
{

inline void* extension(X509* x509, int nid)
{
    return X509_get_ext_d2i(x509, nid, nullptr, nullptr);
}

inline bool hasClientAuthExtendedKeyUsage(EXTENDED_KEY_USAGE* usage)
{
    for (int i = 0; i < sk_ASN1_OBJECT_num(usage); ++i) {
        ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(usage, i);
        if (OBJ_obj2nid(obj) == NID_client_auth) {
            return true;
        }
    }
    return false;
}

inline CertificateType certificateType(const pcsc_cpp::byte_vector& cert)
{
    const unsigned char* certPtr = cert.data();
    auto x509 = SCOPE_GUARD(X509, d2i_X509(nullptr, &certPtr, long(cert.size())));
    if (!x509) {
        THROW(SmartCardChangeRequiredError, "Failed to create X509 object from certificate");
    }
    auto keyUsage = SCOPE_GUARD(ASN1_BIT_STRING, extension(x509.get(), NID_key_usage));
    if (!keyUsage) {
        return CertificateType::NONE;
    }

    static const int KEY_USAGE_NON_REPUDIATION = 1;
    if (ASN1_BIT_STRING_get_bit(keyUsage.get(), KEY_USAGE_NON_REPUDIATION)) {
        return CertificateType::SIGNING;
    }

    static const int KEY_USAGE_DIGITAL_SIGNATURE = 0;
    if (ASN1_BIT_STRING_get_bit(keyUsage.get(), KEY_USAGE_DIGITAL_SIGNATURE)) {
        auto extKeyUsage =
            SCOPE_GUARD(EXTENDED_KEY_USAGE, extension(x509.get(), NID_ext_key_usage));
        if (extKeyUsage && hasClientAuthExtendedKeyUsage(extKeyUsage.get())) {
            return CertificateType::AUTHENTICATION;
        }
    }

    return CertificateType::NONE;
}

} // namespace electronic_id
