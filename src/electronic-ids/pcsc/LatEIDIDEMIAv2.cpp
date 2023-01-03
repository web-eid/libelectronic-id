/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

#include "LatEIDIDEMIAv2.hpp"

#include "pcsc-common.hpp"

#include <optional>

using namespace pcsc_cpp;
using namespace electronic_id;

struct LatEIDIDEMIAV2::Private
{
    std::optional<bool> isUpdated;
};

LatEIDIDEMIAV2::LatEIDIDEMIAV2(pcsc_cpp::SmartCard::ptr _card) :
    LatEIDIDEMIACommon(std::move(_card)), data(std::make_unique<Private>())
{
}

LatEIDIDEMIAV2::~LatEIDIDEMIAV2() = default;

bool LatEIDIDEMIAV2::isUpdated() const
{
    if (data->isUpdated.has_value()) {
        return data->isUpdated.value();
    }
    static const auto command = CommandApdu::fromBytes({0x00, 0xA4, 0x02, 0x04, 0x02, 0x50, 0x40});
    const auto response = card->transmit(command);
    data->isUpdated = response.toSW() == 0x9000;
    return data->isUpdated.value();
}

const std::set<SignatureAlgorithm>& LatEIDIDEMIAV2::supportedSigningAlgorithms() const
{
    const static std::set<SignatureAlgorithm> RS256_SIGNATURE_ALGO {
        {SignatureAlgorithm::RS256},
    };
    return isUpdated() ? ELLIPTIC_CURVE_SIGNATURE_ALGOS() : RS256_SIGNATURE_ALGO;
}

const ManageSecurityEnvCmds& LatEIDIDEMIAV2::selectSecurityEnv() const
{
    static const ManageSecurityEnvCmds selectSecurityEnv1Cmds {
        // Activate authentication environment.
        {0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x81},
        // Activate signing environment.
        {0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x42, 0x84, 0x01, 0x9f},
    };
    static const ManageSecurityEnvCmds selectSecurityEnv2Cmds {
        // Activate authentication environment.
        {0x00, 0x22, 0x41, 0xa4, 0x06, 0x80, 0x01, 0x04, 0x84, 0x01, 0x82},
        // Activate signing environment.
        {0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x54, 0x84, 0x01, 0x9e},
    };
    return isUpdated() ? selectSecurityEnv2Cmds : selectSecurityEnv1Cmds;
}
