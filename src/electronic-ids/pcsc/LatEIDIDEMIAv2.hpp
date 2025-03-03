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

#include "EIDIDEMIA.hpp"

#include <map>

namespace electronic_id
{

class LatEIDIDEMIAV2 : public EIDIDEMIA
{
public:
    explicit LatEIDIDEMIAV2(pcsc_cpp::SmartCard::ptr _card);
    ~LatEIDIDEMIAV2() override;
    PCSC_CPP_DISABLE_COPY_MOVE(LatEIDIDEMIAV2);

private:
    byte_vector getCertificateImpl(const CertificateType type) const override;

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override;
    PinMinMaxLength authPinMinMaxLength() const override { return {4, 12}; }

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;
    PinMinMaxLength signingPinMinMaxLength() const override { return {6, 12}; }

    std::string name() const override { return "LatEID IDEMIA v2"; }
    Type type() const override { return LatEID; }

    KeyInfo authKeyRef() const override;
    KeyInfo signKeyRef() const override;

    const byte_vector& readEF_File(byte_vector file,
                                   std::map<byte_vector, byte_vector>& cache) const;
    const byte_vector& readDCODInfo(byte_type type,
                                    std::map<byte_vector, byte_vector>& cache) const;
    KeyInfo readPrKDInfo(byte_type keyID, std::map<byte_vector, byte_vector>& cache) const;

    struct Private;
    std::unique_ptr<Private> data;
};

} // namespace electronic_id
