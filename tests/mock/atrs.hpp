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

#include "pcsc-mock/pcsc-mock.hpp"

// TODO: expose ATRs from electronic-id.cpp (currently local variables there)
// to avoid duplication.

const PcscMock::byte_vector ESTEID_GEMALTO_V3_5_8_COLD_ATR = {
    0x3b, 0xfa, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0xfe,
    0x65, 0x49, 0x44, 0x20, 0x2f, 0x20, 0x50, 0x4b, 0x49, 0x03};

const PcscMock::byte_vector ESTEID_IDEMIA_V1_ATR = {0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45,
                                                    0x1f, 0x83, 0x00, 0x12, 0x23, 0x3f, 0x53, 0x65,
                                                    0x49, 0x44, 0x0f, 0x90, 0x00, 0xf1};

const PcscMock::byte_vector LATEID_IDEMIA_V1_ATR = {0x3b, 0xdd, 0x18, 0x00, 0x81, 0x31, 0xfe, 0x45,
                                                    0x90, 0x4c, 0x41, 0x54, 0x56, 0x49, 0x41, 0x2d,
                                                    0x65, 0x49, 0x44, 0x90, 0x00, 0x8c};

const PcscMock::byte_vector LATEID_IDEMIA_V2_ATR = {0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45,
                                                    0x1f, 0x83, 0x00, 0x12, 0x42, 0x8f, 0x53, 0x65,
                                                    0x49, 0x44, 0x0f, 0x90, 0x00, 0x20};

const PcscMock::byte_vector FINEID_V3_ATR = {0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31,
                                             0xb8, 0x65, 0xb0, 0x85, 0x03, 0x00, 0xef,
                                             0x12, 0x00, 0xf6, 0x82, 0x90, 0x00};
