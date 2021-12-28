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

#include "LatEIDIDEMIAv1.hpp"

#include "pcsc-common.hpp"

// http://www.unsads.com/specs/IASECC/IAS_ECC_v1.0.1_UK.pdf

using namespace pcsc_cpp;

namespace electronic_id
{

const std::set<SignatureAlgorithm>& LatEIDIDEMIAV1::supportedSigningAlgorithms() const
{
    return RSA_SIGNATURE_ALGOS();
}

const SelectApplicationIDCmds& LatEIDIDEMIAV1::selectApplicationID() const
{
    static const auto selectAppIDCmds = SelectApplicationIDCmds {
        // Main AID.
        EIDIDEMIA::selectApplicationID().MAIN_AID,
        // AWP AID.
        EIDIDEMIA::selectApplicationID().AUTH_AID,
        // QSCD AID is not present in v1, AWP app contains signing code as well.
        EIDIDEMIA::selectApplicationID().AUTH_AID,
    };
    return selectAppIDCmds;
}

const SelectCertificateCmds& LatEIDIDEMIAV1::selectCertificate() const
{
    static const auto selectCertCmds = SelectCertificateCmds {
        // Authentication certificate.
        {0x00, 0xA4, 0x01, 0x0C, 0x02, 0xA0, 0x02},
        // Signing certificate.
        {0x00, 0xA4, 0x01, 0x0C, 0x02, 0xA0, 0x01},
    };
    return selectCertCmds;
}

const ManageSecurityEnvCmds& LatEIDIDEMIAV1::selectSecurityEnv() const
{
    static const auto selectSecurityEnvCmds = ManageSecurityEnvCmds {
        // Activate authentication environment.
        {0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x82},
        // Activate signing environment.
        {0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x81},
    };
    return selectSecurityEnvCmds;
}

} // namespace electronic_id
