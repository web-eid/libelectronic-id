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

#include "LatEIDIDEMIACommon.hpp"

namespace electronic_id
{

class LatEIDIDEMIAV1 : public LatEIDIDEMIACommon
{
public:
    LatEIDIDEMIAV1(pcsc_cpp::SmartCard::ptr _card) : LatEIDIDEMIACommon(std::move(_card)) {}

private:
    std::string name() const override { return "LatEID IDEMIA v1"; }

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;
    SignatureAlgorithm signingSignatureAlgorithm() const override { return SignatureAlgorithm::RS; }

    const SelectApplicationIDCmds& selectApplicationID() const override;
    const SelectCertificateCmds& selectCertificate() const override;
    const ManageSecurityEnvCmds& selectSecurityEnv() const override;

    size_t pinBlockLength() const override { return 0x40; }
    unsigned char signingPinReference() const override { return 0x81; }

    bool useInternalAuthenticateAndRSAWithPKCS1PaddingDuringSigning() const override
    {
        return true;
    }
};

} // namespace electronic_id
