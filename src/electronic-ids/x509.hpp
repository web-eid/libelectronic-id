#pragma once

#include "electronic-id/electronic-id.hpp"

#include "scope.hpp"

#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace electronic_id
{

inline auto toX509(const pcsc_cpp::byte_vector& cert)
{
    if (cert.empty()) {
        throw std::logic_error("empty cert data");
    }
    const unsigned char* certPtr = cert.data();
    auto x509 = SCOPE_GUARD(X509, d2i_X509(nullptr, &certPtr, long(cert.size())));
    if (!x509) {
        throw std::runtime_error("Failed to create X509 object from certificate");
    }
    return x509;
}

inline void* extension(X509* x509, int nid)
{
    return X509_get_ext_d2i(x509, nid, nullptr, nullptr);
}

inline bool hasClientAuthExtendedKeyUsage(EXTENDED_KEY_USAGE* usage)
{
    for (int i = 0; i < sk_ASN1_OBJECT_num(usage); ++i) {
        if (ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(usage, i);
            OBJ_obj2nid(obj) == NID_client_auth) {
            return true;
        }
    }
    return false;
}

inline CertificateType certificateType(const pcsc_cpp::byte_vector& cert)
{
    auto x509 = toX509(cert);

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

inline pcsc_cpp::byte_vector ECconcatToASN1(const pcsc_cpp::byte_vector& data)
{
    auto ecdsa = SCOPE_GUARD(ECDSA_SIG, ECDSA_SIG_new());
    if (ECDSA_SIG_set0(ecdsa.get(), BN_bin2bn(data.data(), int(data.size() / 2), nullptr),
                       BN_bin2bn(&data[data.size() / 2], int(data.size() / 2), nullptr))
        != 1) {
        throw std::runtime_error("ECconcatToASN1: ECDSA_SIG_set0() failed");
    }
    int size = i2d_ECDSA_SIG(ecdsa.get(), nullptr);
    if (size < 1) {
        throw std::runtime_error("ECconcatToASN1: i2d_ECDSA_SIG() failed");
    }
    pcsc_cpp::byte_vector result(size_t(size), 0);
    unsigned char* p = result.data();
    if (i2d_ECDSA_SIG(ecdsa.get(), &p) != size) {
        throw std::runtime_error(
            "ECconcatToASN1: i2d_ECDSA_SIG() result does not match expected size");
    }
    return result;
}

inline const EVP_MD* hashToMD(electronic_id::HashAlgorithm hashAlgo)
{
    switch (hashAlgo) {
    case electronic_id::HashAlgorithm::SHA224:
        return EVP_sha224();
    case electronic_id::HashAlgorithm::SHA256:
        return EVP_sha256();
    case electronic_id::HashAlgorithm::SHA384:
        return EVP_sha384();
    case electronic_id::HashAlgorithm::SHA512:
        return EVP_sha512();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    case electronic_id::HashAlgorithm::SHA3_224:
        return EVP_sha3_224();
    case electronic_id::HashAlgorithm::SHA3_256:
        return EVP_sha3_256();
    case electronic_id::HashAlgorithm::SHA3_384:
        return EVP_sha3_384();
    case electronic_id::HashAlgorithm::SHA3_512:
        return EVP_sha3_512();
#endif
    default:
        throw std::logic_error("hashToMD: unknown hash algorithm");
    }
}

template <typename T>
inline bool verifyDigest(T signAlgo, const pcsc_cpp::byte_vector& der,
                         const pcsc_cpp::byte_vector& digest,
                         const pcsc_cpp::byte_vector& signature)
{
    if (digest.empty() || signature.empty()) {
        throw std::logic_error("verify: digest or signature");
    }
    auto cert = electronic_id::toX509(der);
    EVP_PKEY* key = X509_get0_pubkey(cert.get());
    auto ctx = SCOPE_GUARD(EVP_PKEY_CTX, EVP_PKEY_CTX_new(key, nullptr));
    if (!ctx || EVP_PKEY_verify_init(ctx.get()) != 1) {
        throw std::runtime_error("EVP CTX object creation failed");
    }
    if (EVP_PKEY_base_id(key) == EVP_PKEY_EC) {
        pcsc_cpp::byte_vector sig = ECconcatToASN1(signature);
        return ctx && EVP_PKEY_verify_init(ctx.get()) == 1
            && EVP_PKEY_verify(ctx.get(), sig.data(), sig.size(), digest.data(), digest.size())
            == 1;
    }

    bool isPSS = false;
    if constexpr (std::is_same_v<JsonWebSignatureAlgorithm, T>) {
        isPSS = signAlgo.isRSAWithPSSPadding();
    } else {
        isPSS = (signAlgo & electronic_id::SignatureAlgorithm::PS) > 0;
    }
    if (isPSS) {
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), RSA_PSS_SALTLEN_AUTO);
    } else {
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
    }

    EVP_PKEY_CTX_set_signature_md(ctx.get(), hashToMD(signAlgo));
    return 1
        == EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(), digest.data(),
                           digest.size());
}

} // namespace electronic_id
