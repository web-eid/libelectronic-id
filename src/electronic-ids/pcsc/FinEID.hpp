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

#include "PcscElectronicID.hpp"

namespace electronic_id
{

class FinEIDv3 : public PcscElectronicID
{
public:
    FinEIDv3(pcsc_cpp::SmartCard::ptr _card) : PcscElectronicID(std::move(_card)) {}

private:
    pcsc_cpp::byte_vector getCertificateImpl(const CertificateType type) const override;

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override
    {
        return JsonWebSignatureAlgorithm::PS256;
    }
    PinMinMaxLength authPinMinMaxLength() const override { return {4, 12}; }
    PinRetriesRemainingAndMax authPinRetriesLeftImpl() const override;

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;
    PinMinMaxLength signingPinMinMaxLength() const override { return {6, 12}; }
    PinRetriesRemainingAndMax signingPinRetriesLeftImpl() const override;

    std::string name() const override { return "FinEID v3"; }
    Type type() const override { return FinEID; }

    pcsc_cpp::byte_vector signWithAuthKeyImpl(const pcsc_cpp::byte_vector& pin,
                                              const pcsc_cpp::byte_vector& hash) const override;

    Signature signWithSigningKeyImpl(const pcsc_cpp::byte_vector& pin,
                                     const pcsc_cpp::byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    pcsc_cpp::byte_vector sign(const HashAlgorithm hashAlgo, const pcsc_cpp::byte_vector& hash,
                               const pcsc_cpp::byte_vector& pin,
                               pcsc_cpp::byte_vector::value_type pinReference,
                               PinMinMaxLength pinMinMaxLength,
                               pcsc_cpp::byte_vector::value_type keyReference,
                               pcsc_cpp::byte_vector::value_type signatureAlgo,
                               pcsc_cpp::byte_vector::value_type LE) const;

    PinRetriesRemainingAndMax pinRetriesLeft(pcsc_cpp::byte_vector::value_type pinReference) const;
};

} // namespace electronic_id
