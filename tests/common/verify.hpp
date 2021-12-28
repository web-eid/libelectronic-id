/*
* Copyright (c) 2020-2022 Estonian Information System Authority
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#pragma once

#include "electronic-id/electronic-id.hpp"

#include <openssl/x509.h>
#include <openssl/err.h>

#define SCOPE_GUARD_EX(TYPE, DATA, FREE) std::unique_ptr<TYPE, decltype(&FREE)>(DATA, FREE)
#define SCOPE_GUARD(TYPE, DATA) SCOPE_GUARD_EX(TYPE, DATA, TYPE##_free)

#if OPENSSL_VERSION_NUMBER < 0x10100000L
inline int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s)
{
    if (!r || !s)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif

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
    pcsc_cpp::byte_vector result(size);
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

inline pcsc_cpp::byte_vector calculateDigest(electronic_id::HashAlgorithm hashAlgo,
                                             const pcsc_cpp::byte_vector& data)
{
    pcsc_cpp::byte_vector digest(size_t(EVP_MAX_MD_SIZE));
    const EVP_MD* md = hashToMD(hashAlgo);
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &size, md, nullptr) != 1) {
        throw std::runtime_error("calculateDigest: EVP_Digest failed");
    }
    digest.resize(size);
    return digest;
}

inline bool verify(electronic_id::HashAlgorithm hashAlgo, const pcsc_cpp::byte_vector& der,
                   const pcsc_cpp::byte_vector& data, const pcsc_cpp::byte_vector& signature,
                   bool isPSS)
{
    if (der.empty() || data.empty() || signature.empty()) {
        throw std::logic_error("verify: empty der, data or signature");
    }
    const unsigned char* p = der.data();
    auto cert = SCOPE_GUARD(X509, d2i_X509(nullptr, &p, long(der.size())));
    if (!cert) {
        throw std::runtime_error("verify: X509 object creation failed");
    }
    auto key = SCOPE_GUARD(EVP_PKEY, X509_get_pubkey(cert.get()));
    if (!key) {
        throw std::runtime_error("verify: X509 public key object creation failed");
    }
    pcsc_cpp::byte_vector sig =
        EVP_PKEY_base_id(key.get()) == EVP_PKEY_EC ? ECconcatToASN1(signature) : signature;
    auto ctx = SCOPE_GUARD(EVP_MD_CTX, EVP_MD_CTX_new());
    EVP_PKEY_CTX* pkctx = nullptr;
    if (EVP_DigestVerifyInit(ctx.get(), &pkctx, hashToMD(hashAlgo), nullptr, key.get()) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("verify: EVP_DigestVerifyInit() failed");
    }
    if (isPSS) {
        EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_AUTO);
    }
    return 1 == EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), data.data(), data.size());
}
