// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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

// Workaround gcc 14.2 bug
struct VectorComparator
{
    PCSC_CPP_CONSTEXPR_VECTOR bool operator()(const std::vector<unsigned char>& a,
                                              const std::vector<unsigned char>& b) const
    {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    }
};

} // namespace electronic_id
