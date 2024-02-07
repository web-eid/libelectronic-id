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

#include "LatEIDIDEMIAv2.hpp"

#include "pcsc-common.hpp"

#include <optional>

using namespace pcsc_cpp;
using namespace electronic_id;

struct KeyInfo
{
    bool isECC;
    byte_type id;
};

struct LatEIDIDEMIAV2::Private
{
    std::optional<KeyInfo> authKeyInfo;
    std::optional<KeyInfo> signKeyInfo;
};

namespace
{
constexpr byte_type DEFAULT_AUTH_KEY_ID = 0x81;
constexpr byte_type DEFAULT_SIGN_KEY_ID = 0x9F;

inline byte_vector readEF_File(const SmartCard& card, const byte_vector& file)
{
    auto response = card.transmit({0x00, 0xA4, 0x02, 0x04, file, 0x00});
    if (!response.isOK()) {
        THROW(SmartCardError, "Failed to read EF file");
    }
    static const byte_vector findLength {0x80, 0x02};
    auto pos = std::search(response.data.cbegin(), response.data.cend(), findLength.cbegin(),
                           findLength.cend());
    if (pos == response.data.cend()) {
        THROW(SmartCardError, "Failed to read EF file length");
    }
    pos += byte_vector::difference_type(findLength.size());
    return readBinary(card, size_t(*pos << 8) + *(pos + 1), 0xFF);
}

inline byte_vector readEF_PrKD(const SmartCard& card)
{
    static const byte_vector EF_OD {0x50, 0x31};
    const auto info = readEF_File(card, EF_OD);
    static const byte_vector file {0xA0, 0x06, 0x30, 0x04, 0x04, 0x02};
    auto pos = std::search(info.cbegin(), info.cend(), file.cbegin(), file.cend());
    if (pos == info.cend()) {
        THROW(SmartCardError, "EF.PrKD reference not found");
    }
    pos += byte_vector::difference_type(file.size());
    return readEF_File(card, {*pos, *(pos + 1)});
}

inline KeyInfo readPrKDInfo(const SmartCard& card, byte_type keyID)
{
    const auto data = readEF_PrKD(card);
    if (data.empty()) {
        return {false, keyID};
    }
    static const byte_vector needle {0x02, 0x02, 0x00};
    if (auto pos = std::search(data.cbegin(), data.cend(), needle.cbegin(), needle.cend());
        pos != data.cend()) {
        return {data[0] == 0xA0, *(pos + byte_vector::difference_type(needle.size()))};
    }
    return {data[0] == 0xA0, keyID};
}
} // namespace

LatEIDIDEMIAV2::LatEIDIDEMIAV2(pcsc_cpp::SmartCard::ptr _card) :
    LatEIDIDEMIACommon(std::move(_card)), data(std::make_unique<Private>())
{
}

LatEIDIDEMIAV2::~LatEIDIDEMIAV2() = default;

JsonWebSignatureAlgorithm LatEIDIDEMIAV2::authSignatureAlgorithm() const
{
    if (!data->authKeyInfo.has_value()) {
        auto transactionGuard = card->beginTransaction();
        transmitApduWithExpectedResponse(*card, selectApplicationID().MAIN_AID);
        transmitApduWithExpectedResponse(*card, selectApplicationID().AUTH_AID);
        data->authKeyInfo = readPrKDInfo(*card, DEFAULT_AUTH_KEY_ID);
    }
    return data->authKeyInfo->isECC ? JsonWebSignatureAlgorithm::ES384
                                    : JsonWebSignatureAlgorithm::RS256;
}

const std::set<SignatureAlgorithm>& LatEIDIDEMIAV2::supportedSigningAlgorithms() const
{
    if (!data->signKeyInfo.has_value()) {
        auto transactionGuard = card->beginTransaction();
        transmitApduWithExpectedResponse(*card, selectApplicationID().MAIN_AID);
        transmitApduWithExpectedResponse(*card, selectApplicationID().SIGN_AID);
        data->signKeyInfo = readPrKDInfo(*card, DEFAULT_SIGN_KEY_ID);
    }
    const static std::set<SignatureAlgorithm> RS256_SIGNATURE_ALGO {
        {SignatureAlgorithm::RS256},
    };
    return data->signKeyInfo->isECC ? ELLIPTIC_CURVE_SIGNATURE_ALGOS() : RS256_SIGNATURE_ALGO;
}

SignatureAlgorithm LatEIDIDEMIAV2::signingSignatureAlgorithm() const
{
    if (!data->signKeyInfo.has_value()) {
        auto transactionGuard = card->beginTransaction();
        transmitApduWithExpectedResponse(*card, selectApplicationID().MAIN_AID);
        transmitApduWithExpectedResponse(*card, selectApplicationID().SIGN_AID);
        data->signKeyInfo = readPrKDInfo(*card, DEFAULT_SIGN_KEY_ID);
    }
    return data->signKeyInfo->isECC ? SignatureAlgorithm::ES : SignatureAlgorithm::RS;
}

void LatEIDIDEMIAV2::selectAuthSecurityEnv() const
{
    if (!data->authKeyInfo.has_value()) {
        data->authKeyInfo = readPrKDInfo(*card, DEFAULT_AUTH_KEY_ID);
    }
    selectSecurityEnv(*card, 0xA4, data->authKeyInfo->isECC ? 0x04 : 0x02, data->authKeyInfo->id,
                      name());
}

byte_type LatEIDIDEMIAV2::selectSignSecurityEnv() const
{
    if (!data->signKeyInfo.has_value()) {
        data->signKeyInfo = readPrKDInfo(*card, DEFAULT_SIGN_KEY_ID);
    }
    return selectSecurityEnv(*card, 0xB6, data->signKeyInfo->isECC ? 0x54 : 0x42,
                             data->signKeyInfo->id, name());
}
