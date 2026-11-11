// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "PcscElectronicID.hpp"

#include "../TLV.hpp"
#include "../scope.hpp"

#include <algorithm>

using namespace std::string_literals;
using namespace pcsc_cpp;
using namespace electronic_id;

void PcscElectronicID::selectFile(const SmartCard::Session& session, const CommandApdu& command)
{
    const auto response = session.transmit(command);
    if (!response.isOK()) {
        THROW(SmartCardError, "Failed to select file");
    }
}

byte_vector PcscElectronicID::readFile(const SmartCard::Session& session, const CommandApdu& select,
                                       byte_type blockLength)
{
    auto response = session.transmit(select);
    if (!response.isOK()) {
        THROW(SmartCardError, "Failed to select EF file");
    }
    auto fci = TLV(response.data).find(0x62);
    TLV size = fci[0x80];
    if (!size) {
        size = fci[0x81];
    }
    if (!size || size.length != 2) {
        THROW(SmartCardError, "Failed to read EF file length");
    }

    uint16_t length = toSW(*size.begin, *(size.begin + 1));
    byte_vector resultBytes;
    resultBytes.reserve(length);
    while (resultBytes.size() < length) {
        byte_type chunk = byte_type(std::min<size_t>(length - resultBytes.size(), blockLength));
        auto chunkResponse =
            session.transmit(CommandApdu::readBinary(uint16_t(resultBytes.size()), chunk));
        if (chunk > 0 && chunkResponse.data.size() != chunk) {
            THROW(SmartCardError,
                  "Length mismatch, expected "s + std::to_string(chunk) + ", received "
                      + std::to_string(chunkResponse.data.size()) + " bytes");
        }
        resultBytes.insert(resultBytes.end(), chunkResponse.data.cbegin(),
                           chunkResponse.data.cend());
    }
    if (resultBytes.size() != length) {
        THROW(SmartCardError,
              "Length mismatch, expected "s + std::to_string(length) + ", received "
                  + std::to_string(resultBytes.size()) + " bytes");
    }
    return resultBytes;
}

void PcscElectronicID::verifyPin(const SmartCard::Session& session, byte_type p2, byte_vector&& pin,
                                 PinMinMaxLength pinMinMax, byte_type paddingChar) const
{
    ResponseApdu response;

    if (card.readerHasPinPad()) {
        response = session.transmitCTL(CommandApdu::verify(p2, pinMinMax.second, paddingChar), 0,
                                       pinMinMax.first);
    } else {
        auto verifyCommand = CommandApdu::verify(p2, std::move(pin), pinMinMax.second, paddingChar);
        auto clearPinCommand = stdext::make_scope_exit(
            [&verifyCommand]() noexcept { std::move(verifyCommand).clear(); });
        response = session.transmit(verifyCommand);
    }

    // NOTE: in case card-specific error handling logic is needed,
    // move response error handling to ElectronicID.getVerifyPinError().
    switch (response.toSW()) {
        using pcsc_cpp::toSW;
        using enum ResponseApdu::Status;
        using enum VerifyPinFailed::Status;
    case toSW(OK, 0x00):
        return;
    // Fail, retry allowed unless SW2 == 0xc0.
    case toSW(VERIFICATION_FAILED, 0xc0):
        throw VerifyPinFailed(PIN_BLOCKED, &response);
    // Fail, PIN pad PIN entry errors, retry allowed.
    case toSW(VERIFICATION_CANCELLED, 0x00):
        throw VerifyPinFailed(PIN_ENTRY_TIMEOUT, &response);
    case toSW(VERIFICATION_CANCELLED, 0x01):
        throw VerifyPinFailed(PIN_ENTRY_CANCEL, &response);
    case toSW(VERIFICATION_CANCELLED, 0x03):
        throw VerifyPinFailed(INVALID_PIN_LENGTH, &response);
    case toSW(VERIFICATION_CANCELLED, 0x04):
        throw VerifyPinFailed(PIN_ENTRY_DISABLED, &response);
    // Fail, invalid PIN length, retry allowed.
    case toSW(WRONG_LENGTH, 0x00):
    case toSW(WRONG_PARAMETERS, 0x80):
        throw VerifyPinFailed(INVALID_PIN_LENGTH, &response);
    // Fail, retry not allowed.
    case toSW(COMMAND_NOT_ALLOWED, 0x83):
    case toSW(COMMAND_NOT_ALLOWED, 0x84):
        throw VerifyPinFailed(PIN_BLOCKED, &response);
    default:
        if (response.sw1 == VERIFICATION_FAILED) {
            throw VerifyPinFailed(RETRY_ALLOWED, &response, response.sw2 & 0x0f);
        }

        // There are other known response codes like 0x6985 (old and new are PIN same), 0x6402
        // (re-entered PIN is different) that only apply during PIN change, we treat them as unknown
        // errors here.

        // Other unknown errors.
        throw VerifyPinFailed(UNKNOWN_ERROR, &response);
    }
}

void PcscElectronicID::selectSecurityEnv(const SmartCard::Session& session, byte_type env,
                                         byte_type signatureAlgo, byte_type keyReference) const
{
    const auto response = session.transmit(
        {0x00, 0x22, 0x41, env, {0x80, 0x01, signatureAlgo, 0x84, 0x01, keyReference}});

    if (!response.isOK()) {
        THROW(SmartCardError, name() + ": Command SET ENV failed with error " + response);
    }
}
