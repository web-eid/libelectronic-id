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

#include "EstEIDIDEMIA.hpp"

#include "pcsc-common.hpp"

// ESTEID specification:
// https://installer.id.ee/media/id2019/TD-ID1-Chip-App.pdf

using namespace electronic_id;

void EstEIDIDEMIAV1::selectAuthSecurityEnv() const
{
    selectSecurityEnv(*card, 0xA4, 0x04, 0x81, name());
}

pcsc_cpp::byte_type EstEIDIDEMIAV1::selectSignSecurityEnv() const
{
    return selectSecurityEnv(*card, 0xB6, 0x54, 0x9f, name());
}

const std::set<SignatureAlgorithm>& EstEIDIDEMIAV1::supportedSigningAlgorithms() const
{
    return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
}
