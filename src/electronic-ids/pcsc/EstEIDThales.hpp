// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
    PinInfo authPinInfoImpl(const SmartCard::Session& session) const override
    {
        // Some EstEID cards must set PIN-s first to use card
        return pinRetriesLeft(session, authPinReference(), false);
    }
    constexpr int8_t maximumPinRetries() const override { return 3; }
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu signCertFile() const override
    {
        return CommandApdu::selectEF(0x08, {0xAD, 0xF2, 0x34, 0x21});
    }
    constexpr byte_type signingKeyReference() const override { return 0x05; }
    constexpr PinMinMaxLength signingPinMinMaxLength() const override { return {5, 12}; }
    PinInfo signingPinInfoImpl(const SmartCard::Session& session) const override
    {
        // EstEID cards must change PIN2 first to use signing key
        return pinRetriesLeft(session, SIGNING_PIN_REFERENCE, false);
    }
};

} // namespace electronic_id
