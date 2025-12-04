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

#include "pcsc-cpp/pcsc-cpp.hpp"

#include "Context.hpp"
#include "pcsc-cpp/comp_winscard.hpp"

#ifdef _WIN32
#include <Winsock2.h>
#elif !defined(__APPLE__)
#include <arpa/inet.h>
#endif

#include <algorithm>
#include <array>
#include <utility>

// TODO: Someday, maybe SCARD_SHARE_SHARED vs SCARD_SHARE_EXCLUSIVE and SCARD_RESET_CARD on
// disconnect if SCARD_SHARE_EXCLUSIVE, SCARD_LEAVE_CARD otherwise.

namespace
{

constexpr uint32_t VENDOR_HID_GLOBAL = 0x076B;
constexpr uint32_t OMNIKEY_3x21 = 0x3031;
constexpr uint32_t OMNIKEY_6121 = 0x6632;

} // namespace

namespace pcsc_cpp
{

std::string operator+(std::string lhs, const byte_vector& rhs)
{
    lhs.reserve(lhs.size() + rhs.size() * 2);
    std::ostringstream hexStringBuilder(std::move(lhs), std::ios::ate);
    hexStringBuilder << rhs;
    return hexStringBuilder.str();
}

SmartCard Reader::connectToCard() const
{
    return {*this};
}

class CardImpl
{
public:
    explicit CardImpl(const Reader& reader)
    {
        constexpr unsigned requestedProtocol =
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1; // Let PCSC auto-select protocol.
        SCard(Connect, reader.ctx->handle(), reader.name.c_str(), DWORD(SCARD_SHARE_SHARED),
              requestedProtocol, &cardHandle, &_protocol.dwProtocol);

        try {
            DWORD size = 0;
            SCard(Control, cardHandle, DWORD(CM_IOCTL_GET_FEATURE_REQUEST), nullptr, 0U,
                  features.data(), DWORD(features.size() * sizeof(PCSC_TLV_STRUCTURE)), &size);
            if (size == 0 || size % sizeof(PCSC_TLV_STRUCTURE)) {
                return; // No features available or malformed response.
            }
            for (auto& f : features) {
                f.value = ntohl(f.value);
            }

            if (auto ioctl = feature(FEATURE_GET_TLV_PROPERTIES); ioctl != features.cend()) {
                std::array<BYTE, 256> buf {};
                SCard(Control, cardHandle, ioctl->value, nullptr, 0U, buf.data(), DWORD(buf.size()),
                      &size);
                for (auto p = buf.cbegin(); DWORD(std::distance(buf.cbegin(), p)) < size;) {
                    auto tag = TLV_PROPERTIES(*p++);
                    uint32_t value {};
                    for (unsigned int i = 0, len = *p++; i < len; ++i)
                        value |= uint32_t(*p++) << 8 * i;
                    if (tag == TLV_PROPERTY_wIdVendor)
                        id_vendor = value;
                    if (tag == TLV_PROPERTY_wIdProduct)
                        id_product = value;
                }
            }
        } catch (const ScardError&) {
            // Ignore driver errors during card feature requests.
            // TODO: debug(error)
        }
    }

    ~CardImpl() noexcept
    {
        if (cardHandle) {
            // Cannot throw in destructor, so cannot use the SCard() macro here.
            auto result = SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
            cardHandle = 0;
            (void)result; // TODO: Log result here in case it is not OK.
        }
    }

    PCSC_CPP_DISABLE_COPY_MOVE(CardImpl);

    bool readerHasPinPad() const
    {
        // The HID Global OMNIKEY 3x21 Smart Card Reader and HID Global OMNIKEY 6121 Smart Card
        // Reader falsely report that they have PIN pad support even though they don't.
        if (id_vendor == VENDOR_HID_GLOBAL
            && (id_product == OMNIKEY_3x21 || id_product == OMNIKEY_6121))
            return false;
        if (getenv("SMARTCARDPP_NOPINPAD"))
            return false;
        return feature(FEATURE_VERIFY_PIN_START) != features.cend()
            || feature(FEATURE_VERIFY_PIN_DIRECT) != features.cend();
    }

    ResponseApdu transmitBytes(const CommandApdu& commandApdu) const
    {
        byte_vector responseBytes(ResponseApdu::MAX_SIZE, 0);
        auto responseLength = DWORD(responseBytes.size());
        SCard(Transmit, cardHandle, &_protocol, commandApdu.d.data(), DWORD(commandApdu.d.size()),
              nullptr, responseBytes.data(), &responseLength);
        return toResponse(std::move(responseBytes), responseLength);
    }

    ResponseApdu transmitBytesCTL(const CommandApdu& commandApdu, uint16_t lang,
                                  uint8_t minlen) const
    {
        uint8_t PINFrameOffset = 0;
        uint8_t PINLengthOffset = 0;
        byte_vector cmd(sizeof(PIN_VERIFY_STRUCTURE));
        auto* data = (PIN_VERIFY_STRUCTURE*)cmd.data();
        data->bTimerOut = PIN_PAD_PIN_ENTRY_TIMEOUT;
        data->bTimerOut2 = PIN_PAD_PIN_ENTRY_TIMEOUT;
        data->bmFormatString =
            FormatASCII | AlignLeft | uint8_t(PINFrameOffset << 4) | PINFrameOffsetUnitBits;
        data->bmPINBlockString = PINLengthNone << 5 | PINFrameSizeAuto;
        data->bmPINLengthFormat = PINLengthOffsetUnitBits | PINLengthOffset;
        data->wPINMaxExtraDigit = uint16_t(minlen << 8) | 12;
        data->bEntryValidationCondition = ValidOnKeyPressed;
        data->bNumberMessage = CCIDDefaultInvitationMessage;
        data->wLangId = lang;
        data->bMsgIndex = NoInvitationMessage;
        data->ulDataLength = uint32_t(commandApdu.d.size());
        cmd.insert(cmd.cend(), commandApdu.d.cbegin(), commandApdu.d.cend());

        auto ioctl = feature(FEATURE_VERIFY_PIN_START);
        if (feature(FEATURE_VERIFY_PIN_START) == features.cend())
            ioctl = feature(FEATURE_VERIFY_PIN_DIRECT);
        byte_vector responseBytes(ResponseApdu::MAX_SIZE, 0);
        auto responseLength = DWORD(responseBytes.size());
        SCard(Control, cardHandle, ioctl->value, cmd.data(), DWORD(cmd.size()),
              LPVOID(responseBytes.data()), DWORD(responseBytes.size()), &responseLength);

        if (auto finish = feature(FEATURE_VERIFY_PIN_FINISH); finish != features.cend()) {
            responseLength = DWORD(responseBytes.size());
            SCard(Control, cardHandle, finish->value, nullptr, 0U, LPVOID(responseBytes.data()),
                  DWORD(responseBytes.size()), &responseLength);
        }

        return toResponse(std::move(responseBytes), responseLength);
    }

    void beginTransaction() const { SCard(BeginTransaction, cardHandle); }

    void endTransaction() const { SCard(EndTransaction, cardHandle, DWORD(SCARD_LEAVE_CARD)); }

    SmartCard::Protocol protocol() const
    {
        switch (_protocol.dwProtocol) {
            using enum SmartCard::Protocol;
        case SCARD_PROTOCOL_UNDEFINED:
            return UNDEFINED;
        case SCARD_PROTOCOL_T0:
            return T0;
        case SCARD_PROTOCOL_T1:
            return T1;
        default:
            THROW(Error, "Unsupported card protocol: " + std::to_string(_protocol.dwProtocol));
        }
    }

private:
    SCARDHANDLE cardHandle {};
    SCARD_IO_REQUEST _protocol {SCARD_PROTOCOL_UNDEFINED, sizeof(SCARD_IO_REQUEST)};
    std::array<PCSC_TLV_STRUCTURE, FEATURE_CCID_ESC_COMMAND> features {};
    uint32_t id_vendor {};
    uint32_t id_product {};

    constexpr decltype(features)::const_iterator feature(DRIVER_FEATURES tag) const
    {
        return std::find_if(features.cbegin(), features.cend(),
                            [tag](PCSC_TLV_STRUCTURE tlv) { return tlv.tag == tag; });
    }

    ResponseApdu toResponse(byte_vector&& responseBytes, size_t responseLength) const
    {
        if (responseLength > responseBytes.size()) {
            THROW(Error, "SCardTransmit: received more bytes than buffer size");
        }
        if (responseLength < 2) {
            THROW(Error, "SCardTransmit: Need at least 2 bytes for creating ResponseApdu");
        }
        responseBytes.resize(responseLength);

        PCSC_CPP_WARNING_PUSH
        PCSC_CPP_WARNING_DISABLE_GCC("-Warray-bounds") // avoid GCC 13 false positive warning
        // SW1 and SW2 are in the end
        byte_type sw1 = responseBytes[responseLength - 2];
        byte_type sw2 = responseBytes[responseLength - 1];
        responseBytes.resize(responseLength - 2);
        PCSC_CPP_WARNING_POP

        ResponseApdu response {sw1, sw2, std::move(responseBytes)};

        // Let expected errors through for handling in upper layers or in if blocks below.
        switch (response.sw1) {
            using enum ResponseApdu::Status;
        case OK:
        case MORE_DATA_AVAILABLE:
        case WRONG_LE_LENGTH:
        case VERIFICATION_FAILED:
        case VERIFICATION_CANCELLED:
        case WRONG_LENGTH:
        case COMMAND_NOT_ALLOWED:
        case WRONG_PARAMETERS:
            return response;
        default:
            THROW(Error,
                  "Error response: '" + response + "', protocol "
                      + std::to_string(_protocol.dwProtocol));
        }
    }
};

SmartCard::Session::Session(const CardImpl& card) : card(card)
{
    card.beginTransaction();
}

SmartCard::Session::~Session() noexcept
{
    try {
        card.endTransaction();
    } catch (...) {
        // Ignore exceptions in destructor.
    }
}

ResponseApdu SmartCard::Session::transmit(const CommandApdu& command) const
{
    auto response = card.transmitBytes(command);
    if (response.sw1 == ResponseApdu::WRONG_LE_LENGTH) {
        response = card.transmitBytes(CommandApdu(command, response.sw2));
    }
    if (response.sw1 == ResponseApdu::MORE_DATA_AVAILABLE) {
        auto getResponseCommand = CommandApdu::getResponse();
        while (response.sw1 == ResponseApdu::MORE_DATA_AVAILABLE) {
            getResponseCommand.d[4] = response.sw2;
            auto newResponse = card.transmitBytes(getResponseCommand);
            response.sw1 = newResponse.sw1;
            response.sw2 = newResponse.sw2;
            response.data.insert(response.data.end(), newResponse.data.cbegin(),
                                 newResponse.data.cend());
        }
    }
    return response;
}

ResponseApdu SmartCard::Session::transmitCTL(const CommandApdu& command, uint16_t lang,
                                             uint8_t minlen) const
{
    return card.transmitBytesCTL(command, lang, minlen);
}

bool SmartCard::Session::readerHasPinPad() const
{
    return card.readerHasPinPad();
}

SmartCard::SmartCard(Reader _reader) :
    reader(std::move(_reader)), card(std::make_unique<CardImpl>(reader))
{
}

SmartCard::SmartCard() noexcept = default;
SmartCard::SmartCard(SmartCard&& other) noexcept = default;
SmartCard::~SmartCard() noexcept = default;

SmartCard::Session SmartCard::beginSession() const
{
    REQUIRE_NON_NULL(card)
    return {*card};
}

SmartCard::Protocol SmartCard::protocol() const
{
    return card ? card->protocol() : Protocol::UNDEFINED;
}

bool SmartCard::readerHasPinPad() const
{
    return card ? card->readerHasPinPad() : false;
}

} // namespace pcsc_cpp
