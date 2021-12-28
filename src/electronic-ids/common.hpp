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

#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include <set>

namespace electronic_id
{

// Use functions instead of global variables to avoid the "static initialization fiasco".
const std::set<SignatureAlgorithm>& ELLIPTIC_CURVE_SIGNATURE_ALGOS();
const std::set<SignatureAlgorithm>& RSA_SIGNATURE_ALGOS();

inline void validateAuthHashLength(const JsonWebSignatureAlgorithm authSignatureAlgorithm,
                                   const std::string& eidName, const pcsc_cpp::byte_vector& hash)
{
    if (authSignatureAlgorithm.hashByteLength() != hash.size()) {
        THROW(SmartCardChangeRequiredError,
              "Electronic ID " + eidName + " only supports hash size "
                  + std::to_string(authSignatureAlgorithm.hashByteLength())
                  + " during authentication, but hash with size " + std::to_string(hash.size())
                  + " was given");
    }
}

inline void validateSigningHash(const ElectronicID& eid, const HashAlgorithm hashAlgo,
                                const pcsc_cpp::byte_vector& hash)
{
    if (!eid.isSupportedSigningHashAlgorithm(hashAlgo)) {
        THROW(SmartCardChangeRequiredError,
              "Electronic ID " + eid.name() + " does not support hash algorithm "
                  + std::string(hashAlgo) + " during signing");
    }

    if (hashAlgo.hashByteLength() != hash.size()) {
        THROW(ArgumentFatalError,
              "Hash size " + std::to_string(hash.size()) + " does not match hash algorithm "
                  + std::string(hashAlgo) + " ouput length "
                  + std::to_string(hashAlgo.hashByteLength()));
    }
}

inline pcsc_cpp::byte_vector addRSAOID(const HashAlgorithm hashAlgo,
                                       const pcsc_cpp::byte_vector& hash)
{
    pcsc_cpp::byte_vector oidAndHash = HashAlgorithm::rsaOID(hashAlgo);
    oidAndHash.insert(oidAndHash.cend(), hash.cbegin(), hash.cend());
    return oidAndHash;
}

} // namespace electronic_id
