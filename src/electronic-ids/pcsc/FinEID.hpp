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

#include "EIDThales.hpp"

namespace electronic_id
{

class FinEIDv4 : public EIDThales
{
public:
    using EIDThales::EIDThales;

protected:
    std::string name() const override { return "FinEID v4"; }
    Type type() const override { return FinEID; }
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu authCertFile() const override
    {
        return CommandApdu::selectEF(0x08, {0x43, 0x31});
    }
    constexpr byte_type authPinReference() const override { return 0x11; }
    constexpr int8_t maximumPinRetries() const override { return 5; }
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu signCertFile() const override
    {
        return CommandApdu::selectEF(0x08, {0x50, 0x16, 0x43, 0x32});
    }
    constexpr byte_type signingKeyReference() const override { return 0x02; }
    constexpr PinMinMaxLength signingPinMinMaxLength() const override { return {6, 12}; }
};

class FinEIDv3 : public FinEIDv4
{
public:
    using FinEIDv4::FinEIDv4;

protected:
    std::string name() const override { return "FinEID v3"; }
    constexpr JsonWebSignatureAlgorithm authSignatureAlgorithm() const override
    {
        return JsonWebSignatureAlgorithm::PS256;
    }
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu signCertFile() const override
    {
        return CommandApdu::selectEF(0x08, {0x50, 0x16, 0x43, 0x35});
    }
    constexpr byte_type signingKeyReference() const override { return 0x03; }
    byte_vector signWithAuthKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                    const byte_vector& hash) const override
    {
        return sign(session, authSignatureAlgorithm().hashAlgorithm(), hash, std::move(pin),
                    authPinReference(), authPinMinMaxLength(), AUTH_KEY_REFERENCE, RSA_PSS_ALGO);
    }

    static constexpr byte_type RSA_PSS_ALGO = 0x05;
};

} // namespace electronic_id
