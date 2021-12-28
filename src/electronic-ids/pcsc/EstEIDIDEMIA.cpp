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

#include "EstEIDIDEMIA.hpp"

#include "pcsc-common.hpp"

// ESTEID specification:
// https://installer.id.ee/media/id2019/TD-ID1-Chip-App.pdf

namespace electronic_id
{

const ManageSecurityEnvCmds& EstEIDIDEMIAV1::selectSecurityEnv() const
{
    static const auto selectSecurityEnvCmds = ManageSecurityEnvCmds {
        // Activate authentication environment.
        {0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x04, 0x84, 0x01, 0x81},
        // Activate signing environment.
        {0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x54, 0x84, 0x01, 0x9f},
    };
    return selectSecurityEnvCmds;
}

const std::set<SignatureAlgorithm>& EstEIDIDEMIAV1::supportedSigningAlgorithms() const
{
    return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
}

ElectronicID::Signature EstEIDIDEMIAV1::signWithSigningKeyImpl(const pcsc_cpp::byte_vector& pin,
                                                               const pcsc_cpp::byte_vector& hash,
                                                               const HashAlgorithm hashAlgo) const
{
    static const size_t ECDSA384_INPUT_LENGTH = 384 / 8;
    auto tmp = hash;
    if (tmp.size() < ECDSA384_INPUT_LENGTH) {
        // Zero-pad hashes that are shorter than SHA-384.
        tmp.insert(tmp.cbegin(), ECDSA384_INPUT_LENGTH - tmp.size(), 0x00);
    } else if (tmp.size() > ECDSA384_INPUT_LENGTH) {
        // Truncate hashes that are longer than SHA-384.
        tmp.resize(ECDSA384_INPUT_LENGTH);
    }
    return EIDIDEMIA::signWithSigningKeyImpl(pin, tmp, hashAlgo);
}

} // namespace electronic_id
