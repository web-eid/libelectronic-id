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
    const static std::set<SignatureAlgorithm> RS_ALGOS = {
        SignatureAlgorithm::RS224,   SignatureAlgorithm::RS256,   SignatureAlgorithm::RS384,
        SignatureAlgorithm::RS512,   SignatureAlgorithm::RS3_224, SignatureAlgorithm::RS3_256,
        SignatureAlgorithm::RS3_384, SignatureAlgorithm::RS3_512,
    };
    return RS_ALGOS;
}

} // namespace electronic_id
