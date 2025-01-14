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

#include "PcscElectronicID.hpp"

namespace electronic_id
{

class FinEIDv3 : public PcscElectronicID
{
public:
    using PcscElectronicID::PcscElectronicID;

protected:
    byte_vector getCertificateImpl(const CertificateType type) const override;

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

    byte_vector signWithAuthKeyImpl(byte_vector&& pin, const byte_vector& hash) const override;

    Signature signWithSigningKeyImpl(byte_vector&& pin, const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    byte_vector sign(const HashAlgorithm hashAlgo, const byte_vector& hash, byte_vector&& pin,
                     byte_type pinReference, PinMinMaxLength pinMinMaxLength,
                     byte_type keyReference, byte_type signatureAlgo) const;

    virtual int8_t maximumPinRetries() const { return 5; }
    PinRetriesRemainingAndMax pinRetriesLeft(byte_type pinReference) const;
};

class FinEIDv4 : public FinEIDv3
{
public:
    using FinEIDv3::FinEIDv3;

protected:
    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override
    {
        return JsonWebSignatureAlgorithm::ES384;
    }

    byte_vector getCertificateImpl(const CertificateType type) const override;

    std::string name() const override { return "FinEID v4"; }

    byte_vector signWithAuthKeyImpl(byte_vector&& pin, const byte_vector& hash) const override;

    Signature signWithSigningKeyImpl(byte_vector&& pin, const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;
};

class EstEIDTHALES : public FinEIDv4
{
public:
    using FinEIDv4::FinEIDv4;

protected:
    byte_vector getCertificateImpl(const CertificateType type) const override;

    PinRetriesRemainingAndMax authPinRetriesLeftImpl() const override;

    PinMinMaxLength signingPinMinMaxLength() const override { return {5, 12}; }

    std::string name() const override { return "EstEIDTHALES"; }
    Type type() const override { return EstEID; }

    byte_vector signWithAuthKeyImpl(byte_vector&& pin, const byte_vector& hash) const override;

    Signature signWithSigningKeyImpl(byte_vector&& pin, const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    int8_t maximumPinRetries() const override { return 3; }
};

} // namespace electronic_id
