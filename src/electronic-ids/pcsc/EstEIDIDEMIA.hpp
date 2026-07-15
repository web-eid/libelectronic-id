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

// ESTEID specification:
// https://installer.id.ee/media/id2019/TD-ID1-Chip-App.pdf

namespace electronic_id
{

class EstEIDIDEMIAV1 : public EIDIDEMIA
{
public:
    using EIDIDEMIA::EIDIDEMIA;

    static constexpr byte_type ATR_COSMO_8[] {0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45,
                                              0x1f, 0x83, 0x00, 0x12, 0x23, 0x3f, 0x53, 0x65,
                                              0x49, 0x44, 0x0f, 0x90, 0x00, 0xf1};
    static constexpr byte_type ATR_COSMO_X[] {0x3b, 0xdc, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45,
                                              0x1f, 0x83, 0x00, 0x12, 0x23, 0x3f, 0x54, 0x65,
                                              0x49, 0x44, 0x32, 0x0f, 0x90, 0x00, 0xc3};

private:
    constexpr PinMinMaxLength signingPinMinMaxLength() const override { return {5, 12}; }
    std::string name() const override { return "EstEID IDEMIA v1"; }
    Type type() const override { return EstEID; }
};

} // namespace electronic_id
