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

class EstEIDThales : public EIDThales
{
public:
    using EIDThales::EIDThales;

protected:
    std::string name() const override { return "EstEIDThales"; }
    Type type() const override { return EstEID; }
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu authCertFile() const override
    {
        return CommandApdu::selectEF(0x08, {0xAD, 0xF1, 0x34, 0x11});
    }
    constexpr byte_type authPinReference() const override { return 0x81; }
    constexpr int8_t maximumPinRetries() const override { return 3; }
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu signCertFile() const override
    {
        return CommandApdu::selectEF(0x08, {0xAD, 0xF2, 0x34, 0x21});
    }
    constexpr byte_type signingKeyReference() const override { return 0x05; }
    constexpr PinMinMaxLength signingPinMinMaxLength() const override { return {5, 12}; }
};

} // namespace electronic_id