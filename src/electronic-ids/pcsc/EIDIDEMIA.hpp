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

class EIDIDEMIA : public PcscElectronicID
{
public:
    explicit EIDIDEMIA(pcsc_cpp::SmartCard::ptr _card) : PcscElectronicID(std::move(_card)) {}

protected:
    byte_vector getCertificateImpl(const CertificateType type) const override;

    PinRetriesRemainingAndMax authPinRetriesLeftImpl() const override;
    virtual void selectAuthSecurityEnv() const = 0;
    byte_vector signWithAuthKeyImpl(byte_vector&& pin, const byte_vector& hash) const override;

    PinRetriesRemainingAndMax signingPinRetriesLeftImpl() const override;
    virtual pcsc_cpp::byte_type selectSignSecurityEnv() const = 0;
    Signature signWithSigningKeyImpl(byte_vector&& pin, const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    PinRetriesRemainingAndMax pinRetriesLeft(byte_type pinReference) const;

    void selectADF1() const;
    void selectADF2() const;
};

} // namespace electronic_id
