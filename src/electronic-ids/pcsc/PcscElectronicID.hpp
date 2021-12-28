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

#include "electronic-id/electronic-id.hpp"

#include "../common.hpp"

namespace electronic_id
{

class PcscElectronicID : public ElectronicID
{
public:
    PcscElectronicID(pcsc_cpp::SmartCard::ptr _card) : ElectronicID(std::move(_card)) {}

protected:
    pcsc_cpp::byte_vector getCertificate(const CertificateType type) const override
    {
        auto transactionGuard = card->beginTransaction();
        return getCertificateImpl(type);
    }

    pcsc_cpp::byte_vector signWithAuthKey(const pcsc_cpp::byte_vector& pin,
                                          const pcsc_cpp::byte_vector& hash) const override
    {
        validateAuthHashLength(authSignatureAlgorithm(), name(), hash);

        auto transactionGuard = card->beginTransaction();
        return signWithAuthKeyImpl(pin, hash);
    }

    Signature signWithSigningKey(const pcsc_cpp::byte_vector& pin,
                                 const pcsc_cpp::byte_vector& hash,
                                 const HashAlgorithm hashAlgo) const override
    {
        validateSigningHash(*this, hashAlgo, hash);

        auto transactionGuard = card->beginTransaction();
        return signWithSigningKeyImpl(pin, hash, hashAlgo);
    }

    PinRetriesRemainingAndMax signingPinRetriesLeft() const override
    {
        auto transactionGuard = card->beginTransaction();
        return signingPinRetriesLeftImpl();
    }

    ElectronicID::PinRetriesRemainingAndMax authPinRetriesLeft() const override
    {
        auto transactionGuard = card->beginTransaction();
        return authPinRetriesLeftImpl();
    }

    // The following pure virtual *Impl functions are the interface of all
    // PC/SC electronic ID implementations,
    // they have to be implemented when adding a new electronic ID.
    // This design follows the non-virtual interface pattern.

    virtual pcsc_cpp::byte_vector getCertificateImpl(const CertificateType type) const = 0;

    virtual pcsc_cpp::byte_vector signWithAuthKeyImpl(const pcsc_cpp::byte_vector& pin,
                                                      const pcsc_cpp::byte_vector& hash) const = 0;

    virtual PinRetriesRemainingAndMax authPinRetriesLeftImpl() const = 0;

    virtual Signature signWithSigningKeyImpl(const pcsc_cpp::byte_vector& pin,
                                             const pcsc_cpp::byte_vector& hash,
                                             const HashAlgorithm hashAlgo) const = 0;

    virtual PinRetriesRemainingAndMax signingPinRetriesLeftImpl() const = 0;
};

} // namespace electronic_id
