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

#include "electronic-id/electronic-id.hpp"
#include "../TLV.hpp"

#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include <algorithm>

using namespace std::string_literals;

namespace electronic_id
{

inline void selectFile(const pcsc_cpp::SmartCard::Session& session,
                       const pcsc_cpp::CommandApdu& command)
{
    const auto response = session.transmit(command);
    if (!response.isOK()) {
        THROW(SmartCardError, "Failed to select file");
    }
}

inline pcsc_cpp::byte_vector readBinary(const pcsc_cpp::SmartCard::Session& session,
                                        const uint16_t length, pcsc_cpp::byte_type blockLength)
{
    pcsc_cpp::byte_vector resultBytes;
    resultBytes.reserve(length);
    while (resultBytes.size() < length) {
        pcsc_cpp::byte_type chunk =
            pcsc_cpp::byte_type(std::min<size_t>(length - resultBytes.size(), blockLength));
        auto response = session.transmit(
            pcsc_cpp::CommandApdu::readBinary(uint16_t(resultBytes.size()), chunk));
        if (chunk > 0 && response.data.size() != chunk) {
            THROW(SmartCardError,
                  "Length mismatch, expected "s + std::to_string(chunk) + ", received "
                      + std::to_string(response.data.size()) + " bytes");
        }
        resultBytes.insert(resultBytes.end(), response.data.cbegin(), response.data.cend());
    }
    if (resultBytes.size() != length) {
        THROW(SmartCardError,
              "Length mismatch, expected "s + std::to_string(length) + ", received "
                  + std::to_string(resultBytes.size()) + " bytes");
    }
    return resultBytes;
}

inline pcsc_cpp::byte_vector readFile(const pcsc_cpp::SmartCard::Session& session,
                                      const pcsc_cpp::CommandApdu& select,
                                      pcsc_cpp::byte_type blockLength = 0x00)
{
    auto response = session.transmit(select);
    if (!response.isOK()) {
        THROW(SmartCardError, "Failed to select EF file");
    }
    TLV fci(response.data);
    if (fci.tag != 0x62) {
        THROW(SmartCardError, "Failed to read EF file length");
    }
    TLV size = fci[0x80];
    if (!size) {
        size = fci[0x81];
    }
    if (size.length != 2) {
        THROW(SmartCardError, "Failed to read EF file length");
    }
    return readBinary(session, pcsc_cpp::toSW(*size.begin, *(size.begin + 1)), blockLength);
}

PCSC_CPP_CONSTEXPR_VECTOR inline pcsc_cpp::byte_vector
addPaddingToPin(pcsc_cpp::byte_vector&& pin, size_t paddingLength, pcsc_cpp::byte_type paddingChar)
{
    if (pin.capacity() < paddingLength) {
        THROW(ProgrammingError,
              "PIN buffer does not have enough capacity to pad without reallocation");
    }
    if (pin.size() < paddingLength) {
        pin.insert(pin.end(), paddingLength - pin.size(), paddingChar);
    }
    return std::move(pin);
}

inline void verifyPin(const pcsc_cpp::SmartCard::Session& session, pcsc_cpp::byte_type p2,
                      pcsc_cpp::byte_vector&& pin, ElectronicID::PinMinMaxLength pinMinMax,
                      pcsc_cpp::byte_type paddingChar)
{
    pcsc_cpp::ResponseApdu response;

    if (session.readerHasPinPad()) {
        const pcsc_cpp::CommandApdu verifyPin {
            0x00, 0x20, 0x00, p2, pcsc_cpp::byte_vector(pinMinMax.second, paddingChar)};
        response = session.transmitCTL(verifyPin, 0, pinMinMax.first);
    } else {
        const pcsc_cpp::CommandApdu verifyPin {
            0x00, 0x20, 0x00, p2, addPaddingToPin(std::move(pin), pinMinMax.second, paddingChar)};
        response = session.transmit(verifyPin);
    }

    // NOTE: in case card-specific error handling logic is needed,
    // move response error handling to ElectronicID.getVerifyPinError().
    switch (response.toSW()) {
        using pcsc_cpp::toSW;
        using enum pcsc_cpp::ResponseApdu::Status;
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

inline pcsc_cpp::byte_vector internalAuthenticate(const pcsc_cpp::SmartCard::Session& session,
                                                  pcsc_cpp::byte_vector hash,
                                                  const std::string& cardType)
{
    pcsc_cpp::CommandApdu internalAuth {0x00, 0x88, 0x00, 0x00, std::move(hash), 0};
    auto response = session.transmit(internalAuth);

    if (response.sw1 == pcsc_cpp::ResponseApdu::WRONG_LENGTH) {
        THROW(SmartCardError,
              cardType
                  + ": Wrong data length in command INTERNAL AUTHENTICATE argument: " + response);
    }
    if (!response.isOK()) {
        THROW(SmartCardError,
              cardType + ": Command INTERNAL AUTHENTICATE failed with error " + response);
    }

    return std::move(response.data);
}

inline pcsc_cpp::byte_vector computeSignature(const pcsc_cpp::SmartCard::Session& session,
                                              pcsc_cpp::byte_vector hash,
                                              const std::string& cardType)
{
    pcsc_cpp::CommandApdu computeSignature {0x00, 0x2A, 0x9E, 0x9A, std::move(hash), 0};
    auto response = session.transmit(computeSignature);

    if (response.sw1 == pcsc_cpp::ResponseApdu::WRONG_LENGTH) {
        THROW(SmartCardError,
              cardType + ": Wrong data length in command COMPUTE SIGNATURE argument: " + response);
    }
    if (!response.isOK()) {
        THROW(SmartCardError,
              cardType + ": Command COMPUTE SIGNATURE failed with error " + response);
    }

    return std::move(response.data);
}

inline void selectSecurityEnv(const pcsc_cpp::SmartCard::Session& session, pcsc_cpp::byte_type env,
                              pcsc_cpp::byte_type signatureAlgo, pcsc_cpp::byte_type keyReference,
                              const std::string& cardType)
{
    const auto response = session.transmit(
        {0x00, 0x22, 0x41, env, {0x80, 0x01, signatureAlgo, 0x84, 0x01, keyReference}});

    if (!response.isOK()) {
        THROW(SmartCardError, cardType + ": Command SET ENV failed with error " + response);
    }
}

} // namespace electronic_id
