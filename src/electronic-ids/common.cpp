// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "common.hpp"

namespace electronic_id
{

const std::set<SignatureAlgorithm>& ELLIPTIC_CURVE_SIGNATURE_ALGOS()
{
    const static std::set<SignatureAlgorithm> ES_ALGOS = {
        SignatureAlgorithm::ES224,   SignatureAlgorithm::ES256,   SignatureAlgorithm::ES384,
        SignatureAlgorithm::ES512,   SignatureAlgorithm::ES3_224, SignatureAlgorithm::ES3_256,
        SignatureAlgorithm::ES3_384, SignatureAlgorithm::ES3_512,
    };
    return ES_ALGOS;
}

const std::set<SignatureAlgorithm>& RSA_SIGNATURE_ALGOS()
{
    // SHA3+RSA (RS3_*, PS3_*) omitted: no card implementation (PCSC or PKCS#11) supports it.
    const static std::set<SignatureAlgorithm> RS_ALGOS = {
        SignatureAlgorithm::RS224,
        SignatureAlgorithm::RS256,
        SignatureAlgorithm::RS384,
        SignatureAlgorithm::RS512,
    };
    return RS_ALGOS;
}

} // namespace electronic_id
