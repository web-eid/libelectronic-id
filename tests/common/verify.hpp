/*
* Copyright (c) 2020-2024 Estonian Information System Authority
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
#include "electronic-ids/x509.hpp"

inline pcsc_cpp::byte_vector calculateDigest(electronic_id::HashAlgorithm hashAlgo,
                                             const pcsc_cpp::byte_vector& data)
{
    const EVP_MD* md = electronic_id::hashToMD(hashAlgo);
    pcsc_cpp::byte_vector digest(size_t(EVP_MD_size(md)));
    auto size = unsigned(digest.size());
    if (EVP_Digest(data.data(), data.size(), digest.data(), &size, md, nullptr) != 1 || digest.size() != size) {
        throw std::runtime_error("calculateDigest: EVP_Digest failed");
    }
    return digest;
}

inline bool verify(electronic_id::HashAlgorithm hashAlgo, const pcsc_cpp::byte_vector& der,
                   const pcsc_cpp::byte_vector& data, const pcsc_cpp::byte_vector& signature,
                   bool isPSS)
{
    if (der.empty() || data.empty() || signature.empty()) {
        throw std::logic_error("verify: data or signature");
    }
    auto cert = electronic_id::toX509(der);
    EVP_PKEY *key = X509_get0_pubkey(cert.get());
    pcsc_cpp::byte_vector sig =
        EVP_PKEY_base_id(key) == EVP_PKEY_EC ? electronic_id::ECconcatToASN1(signature) : signature;
    auto ctx = SCOPE_GUARD(EVP_MD_CTX, EVP_MD_CTX_new());
    EVP_PKEY_CTX* pkctx = nullptr;
    if (EVP_DigestVerifyInit(ctx.get(), &pkctx, hashToMD(hashAlgo), nullptr, key) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("verify: EVP_DigestVerifyInit() failed");
    }
    if (isPSS) {
        EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, RSA_PSS_SALTLEN_AUTO);
    }
    return 1 == EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), data.data(), data.size());
}
