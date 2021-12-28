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

#include "LatEIDIDEMIAv2.hpp"

#include "pcsc-common.hpp"

using namespace pcsc_cpp;

namespace electronic_id
{

const std::set<SignatureAlgorithm>& LatEIDIDEMIAV2::supportedSigningAlgorithms() const
{
    const static std::set<SignatureAlgorithm> RS256_SIGNATURE_ALGO {
        {SignatureAlgorithm::RS256},
    };
    return RS256_SIGNATURE_ALGO;
}

const ManageSecurityEnvCmds& LatEIDIDEMIAV2::selectSecurityEnv() const
{
    static const auto selectSecurityEnvCmds = ManageSecurityEnvCmds {
        // Activate authentication environment.
        {0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x81},
        // Activate signing environment.
        {0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x42, 0x84, 0x01, 0x9f},
    };
    return selectSecurityEnvCmds;
}

} // namespace electronic_id
