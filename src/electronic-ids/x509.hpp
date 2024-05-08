#pragma once

#include "electronic-id/electronic-id.hpp"

#include "common.hpp"
#include "scope.hpp"

#include <openssl/x509v3.h>
#include <openssl/err.h>

namespace electronic_id
{

inline auto make_x509(const pcsc_cpp::byte_vector& cert)
{
    if (const unsigned char* certPtr = cert.data();
        auto x509 = make_unique_ptr(d2i_X509(nullptr, &certPtr, long(cert.size())), X509_free)) {
        return x509;
    }
    THROW(SmartCardChangeRequiredError, "Failed to create X509 object from certificate");
}

template <class T>
inline auto extension(X509* x509, int nid, void (*d)(T*)) noexcept
{
    return make_unique_ptr(static_cast<T*>(X509_get_ext_d2i(x509, nid, nullptr, nullptr)), d);
}

inline bool hasClientAuthExtendedKeyUsage(EXTENDED_KEY_USAGE* usage) noexcept
{
    for (auto count = sk_ASN1_OBJECT_num(usage), i = 0; i < count; ++i) {
        if (ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(usage, i);
            OBJ_obj2nid(obj) == NID_client_auth) {
            return true;
        }
    }
    return false;
}

inline CertificateType certificateType(const pcsc_cpp::byte_vector& cert)
{
    auto x509 = make_x509(cert);
    auto keyUsage = extension(x509.get(), NID_key_usage, ASN1_BIT_STRING_free);
    if (!keyUsage) {
        return CertificateType::NONE;
    }

    static const int KEY_USAGE_NON_REPUDIATION = 1;
    if (ASN1_BIT_STRING_get_bit(keyUsage.get(), KEY_USAGE_NON_REPUDIATION)) {
        return CertificateType::SIGNING;
    }

    static const int KEY_USAGE_DIGITAL_SIGNATURE = 0;
    if (ASN1_BIT_STRING_get_bit(keyUsage.get(), KEY_USAGE_DIGITAL_SIGNATURE)) {
        if (auto extKeyUsage = extension(x509.get(), NID_ext_key_usage, EXTENDED_KEY_USAGE_free);
            extKeyUsage && hasClientAuthExtendedKeyUsage(extKeyUsage.get())) {
            return CertificateType::AUTHENTICATION;
        }
    }

    return CertificateType::NONE;
}

inline JsonWebSignatureAlgorithm getAuthAlgorithmFromCert(const pcsc_cpp::byte_vector& cert)
{
    auto x509 = make_x509(cert);
    EVP_PKEY* key = X509_get0_pubkey(x509.get());
    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_RSA:
        return JsonWebSignatureAlgorithm::RS256;
    case EVP_PKEY_EC:
        break;
    default:
        THROW(SmartCardChangeRequiredError, "Unsupported KEY type");
    }

    switch (auto keyBitLength = EVP_PKEY_bits(key)) {
    case 256:
        return JsonWebSignatureAlgorithm::ES256;
    case 384:
        return JsonWebSignatureAlgorithm::ES384;
    case 512:
    case 521: // secp521r1
        return JsonWebSignatureAlgorithm::ES512;
    default:
        THROW(SmartCardChangeRequiredError,
              "EVP_PKEY_bits() returned an unsupported key size: " + std::to_string(keyBitLength));
    }
}

inline const std::set<SignatureAlgorithm>&
getSignAlgorithmFromCert(const pcsc_cpp::byte_vector& cert)
{
    auto x509 = make_x509(cert);
    switch (EVP_PKEY_base_id(X509_get0_pubkey(x509.get()))) {
    case EVP_PKEY_RSA:
        return RSA_SIGNATURE_ALGOS();
    case EVP_PKEY_EC:
        return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
    default:
        THROW(SmartCardChangeRequiredError, "Unsupported KEY type");
    }
}

} // namespace electronic_id
