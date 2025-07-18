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

#include "../TLV.hpp"

#include "pcsc-common.hpp"

#include <array>
#include <optional>

using namespace pcsc_cpp;
using namespace electronic_id;

struct LatEIDIDEMIAV2::Private
{
    std::map<byte_vector, byte_vector, VectorComparator> authCache;
    std::map<byte_vector, byte_vector, VectorComparator> signCache;
    std::optional<KeyInfo> authKeyInfo;
    std::optional<KeyInfo> signKeyInfo;
};

namespace
{

const byte_vector EF_OD {0x50, 0x31};
constexpr byte_type PRIV_FILE_REF = 0xA0;
constexpr byte_type CERT_FILE_REF = 0xA4;

} // namespace

LatEIDIDEMIAV2::LatEIDIDEMIAV2(SmartCard&& _card) :
    EIDIDEMIA(std::move(_card)), data(std::make_unique<Private>())
{
}

LatEIDIDEMIAV2::~LatEIDIDEMIAV2() = default;

byte_vector LatEIDIDEMIAV2::getCertificateImpl(const pcsc_cpp::SmartCard::Session& session,
                                               const CertificateType type) const
{
    selectMain(session);
    type.isAuthentication() ? selectADF1(session) : selectADF2(session);
    auto info = readDCODInfo(session, CERT_FILE_REF,
                             type.isAuthentication() ? data->authCache : data->signCache);
    if (TLV id = TLV::path(info, 0x30, 0xA1, 0x30, 0x30, 0x04)) {
        return readFile(session, CommandApdu::selectEF(0x02, {id.begin, id.end}));
    }
    THROW(SmartCardError, "EF.CD reference not found");
}

JsonWebSignatureAlgorithm LatEIDIDEMIAV2::authSignatureAlgorithm() const
{
    if (!data->authKeyInfo.has_value()) {
        auto session = card.beginSession();
        selectADF1(session);
        authKeyRef(session);
    }
    return data->authKeyInfo->isECC ? JsonWebSignatureAlgorithm::ES384
                                    : JsonWebSignatureAlgorithm::RS256;
}

const std::set<SignatureAlgorithm>& LatEIDIDEMIAV2::supportedSigningAlgorithms() const
{
    if (!data->signKeyInfo.has_value()) {
        auto session = card.beginSession();
        selectADF2(session);
        signKeyRef(session);
    }
    const static std::set<SignatureAlgorithm> RS256_SIGNATURE_ALGO {
        {SignatureAlgorithm::RS256},
    };
    return data->signKeyInfo->isECC ? ELLIPTIC_CURVE_SIGNATURE_ALGOS() : RS256_SIGNATURE_ALGO;
}

EIDIDEMIA::KeyInfo LatEIDIDEMIAV2::authKeyRef(const pcsc_cpp::SmartCard::Session& session) const
{
    if (!data->authKeyInfo.has_value()) {
        data->authKeyInfo =
            readPrKDInfo(session, EIDIDEMIA::authKeyRef(session).id, data->authCache);
    }
    return data->authKeyInfo.value();
}

EIDIDEMIA::KeyInfo LatEIDIDEMIAV2::signKeyRef(const pcsc_cpp::SmartCard::Session& session) const
{
    if (!data->signKeyInfo.has_value()) {
        data->signKeyInfo =
            readPrKDInfo(session, EIDIDEMIA::signKeyRef(session).id, data->signCache);
    }
    return data->signKeyInfo.value();
}

template <class C>
TLV LatEIDIDEMIAV2::readEF_File(const SmartCard::Session& session, byte_vector file, C& cache) const
{
    if (auto it = cache.find(file); it != cache.end()) {
        return TLV(it->second);
    }
    return TLV(cache[std::move(file)] = readFile(session, CommandApdu::selectEF(0x02, file)));
}

template <class C>
TLV LatEIDIDEMIAV2::readDCODInfo(const pcsc_cpp::SmartCard::Session& session, byte_type type,
                                 C& cache) const
{
    const auto info = readEF_File(session, EF_OD, cache);
    for (TLV ref(info); ref; ++ref) {
        if (ref.tag != type) {
            continue;
        }
        if (auto file = ref[0x30][0x04]; file && file.length == 2) {
            return readEF_File(session, {file.begin, file.end}, cache);
        }
    }
    THROW(SmartCardError, "EF.DCOD reference not found");
}

template <class C>
EIDIDEMIA::KeyInfo LatEIDIDEMIAV2::readPrKDInfo(const pcsc_cpp::SmartCard::Session& session,
                                                byte_type keyID, C& cache) const
{
    TLV prKD = readDCODInfo(session, PRIV_FILE_REF, cache);
    if (!prKD) {
        THROW(SmartCardError, "EF.PrKD reference not found");
    }
    TLV key = prKD[0x30];
    key = TLV::path(++key, 0x30, 0x02);
    return {key.length == 2 ? *std::next(key.begin) : keyID, prKD.tag == 0xA0};
}
