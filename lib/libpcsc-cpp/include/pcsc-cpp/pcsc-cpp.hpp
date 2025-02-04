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

#include "flag-set-cpp/flag_set.hpp"

#include <memory>
#include <vector>
#include <limits>

// The rule of five (C++ Core guidelines C.21).
#define PCSC_CPP_DISABLE_COPY_MOVE(Class)                                                          \
    Class(const Class&) = delete;                                                                  \
    Class& operator=(const Class&) = delete;                                                       \
    Class(Class&&) = delete;                                                                       \
    Class& operator=(Class&&) = delete

#ifdef WIN32
#define PCSC_CPP_WARNING_PUSH __pragma(warning(push))
#define PCSC_CPP_WARNING_POP __pragma(warning(pop))
#define PCSC_CPP_WARNING_DISABLE_CLANG(text)
#define PCSC_CPP_WARNING_DISABLE_GCC(text)
#define PCSC_CPP_WARNING_DISABLE_MSVC(number) __pragma(warning(disable : number))
#else
#define PCSC_CPP_DO_PRAGMA(text) _Pragma(#text)
#define PCSC_CPP_WARNING_PUSH PCSC_CPP_DO_PRAGMA(GCC diagnostic push)
#define PCSC_CPP_WARNING_POP PCSC_CPP_DO_PRAGMA(GCC diagnostic pop)
#if __clang__
#define PCSC_CPP_WARNING_DISABLE_CLANG(text) PCSC_CPP_DO_PRAGMA(clang diagnostic ignored text)
#else
#define PCSC_CPP_WARNING_DISABLE_CLANG(text)
#endif
#define PCSC_CPP_WARNING_DISABLE_GCC(text) PCSC_CPP_DO_PRAGMA(GCC diagnostic ignored text)
#define PCSC_CPP_WARNING_DISABLE_MSVC(text)
#endif

#ifdef __cpp_lib_constexpr_vector
#define PCSC_CPP_CONSTEXPR_VECTOR constexpr
#else
#define PCSC_CPP_CONSTEXPR_VECTOR
#endif

namespace pcsc_cpp
{

using byte_type = unsigned char;
using byte_vector = std::vector<byte_type>;
#ifdef _WIN32
using string_t = std::wstring;
#else
using string_t = std::string;
#endif

/** Opaque class that wraps the PC/SC resource manager context. */
class Context;
using ContextPtr = std::shared_ptr<Context>;

/** Returns the value of the response status bytes SW1 and SW2 as a single status word SW. */
constexpr uint16_t toSW(byte_type sw1, byte_type sw2) noexcept
{
    return uint16_t(sw1 << 8) | sw2;
}

/** Convert bytes to hex string. */
std::ostream& operator<<(std::ostream& os, const pcsc_cpp::byte_vector& data);

std::string operator+(std::string lhs, const byte_vector& rhs);

/** Struct that wraps response APDUs. */
struct ResponseApdu
{
    enum Status : byte_type {
        OK = 0x90,
        MORE_DATA_AVAILABLE = 0x61,
        VERIFICATION_FAILED = 0x63,
        VERIFICATION_CANCELLED = 0x64,
        WRONG_LENGTH = 0x67,
        COMMAND_NOT_ALLOWED = 0x69,
        WRONG_PARAMETERS = 0x6a,
        WRONG_LE_LENGTH = 0x6c
    };

    byte_type sw1 {};
    byte_type sw2 {};

    byte_vector data {};

    static constexpr size_t MAX_DATA_SIZE = 256;
    static constexpr size_t MAX_SIZE = MAX_DATA_SIZE + 2; // + sw1 and sw2

    PCSC_CPP_CONSTEXPR_VECTOR static ResponseApdu fromBytes(byte_vector data)
    {
        if (data.size() < 2) {
            throw std::invalid_argument("Need at least 2 bytes for creating ResponseApdu");
        }

        PCSC_CPP_WARNING_PUSH
        PCSC_CPP_WARNING_DISABLE_GCC("-Warray-bounds") // avoid GCC 13 false positive warning
        byte_type sw1 = data[data.size() - 2];
        byte_type sw2 = data[data.size() - 1];
        data.resize(data.size() - 2);
        PCSC_CPP_WARNING_POP

        // SW1 and SW2 are in the end
        return {sw1, sw2, std::move(data)};
    }

    constexpr uint16_t toSW() const noexcept { return pcsc_cpp::toSW(sw1, sw2); }

    constexpr bool isOK() const noexcept { return sw1 == OK && sw2 == 0x00; }

    friend std::string operator+(std::string&& lhs, const ResponseApdu& rhs)
    {
        return std::move(lhs) + rhs.data + byte_vector {rhs.sw1, rhs.sw2};
    }
};

/**
 * Struct that wraps command APDUs.
 *
 * See for example http://cardwerk.com/iso-7816-smart-card-standard/ for a good overview of the
 * ISO 7816 part 4 standard that defines command APDUs.
 */
struct CommandApdu
{
    static constexpr size_t MAX_DATA_SIZE = 255;

    // ISO 7816 part 4, Annex B.1, Case 1
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu(byte_type cls, byte_type ins, byte_type p1,
                                          byte_type p2) : d {cls, ins, p1, p2}
    {
    }

    // ISO 7816 part 4, Annex B.1, Case 2
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu(byte_type cls, byte_type ins, byte_type p1, byte_type p2,
                                          byte_type le) : d {cls, ins, p1, p2, le}
    {
    }

    // ISO 7816 part 4, Annex B.1, Case 3
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu(byte_type cls, byte_type ins, byte_type p1, byte_type p2,
                                          byte_vector data) : d {std::move(data)}
    {
        if (d.size() > MAX_DATA_SIZE) {
            throw std::invalid_argument("Command chaining and extended lenght not supported");
        }
        d.insert(d.begin(), {cls, ins, p1, p2, static_cast<byte_type>(d.size())});
    }

    // ISO 7816 part 4, Annex B.1, Case 4
    PCSC_CPP_CONSTEXPR_VECTOR CommandApdu(byte_type cls, byte_type ins, byte_type p1, byte_type p2,
                                          byte_vector data, byte_type le) :
        CommandApdu {cls, ins, p1, p2, std::move(data)}
    {
#if defined(__GNUC__) && __GNUC__ == 15 // Apply workaround for GCC 15
        d.reserve(d.size() + 1);
#endif
        d.push_back(le);
    }

    constexpr operator const byte_vector&() const { return d; }

    /**
     * A helper function to create a SELECT command APDU.
     *
     * The ISO 7816-4 Section 6.11 SELECT command has the form:
     *   CLA = 0x00
     *   INS = 0xA4
     *   P1  = varies, see below.
     *   P2  = here hard-coded to 0x0C, no FCI (file control information) returned.
     *   Lc and Data field = the file/path/AID identifier bytes.
     *
     * The P1 parameter for the SELECT command controls the selection mode,
     * we use the following modes:
     *   0x04 = Select AID (application identifier),
     *          direct selection by DF (dedicated file, directory) name.
     *   0x08 = Select from MF (master file, root directory).
     *   0x09 = Select from current DF.
     */
    static PCSC_CPP_CONSTEXPR_VECTOR CommandApdu select(byte_type p1, byte_vector file)
    {
        return {0x00, 0xA4, p1, 0x0C, std::move(file)};
    }

    byte_vector d;
};

/** Opaque class that wraps the PC/SC smart card resources like card handle and I/O protocol. */
class CardImpl;
using CardImplPtr = std::unique_ptr<CardImpl>;

/** PIN pad PIN entry timer timeout */
constexpr uint8_t PIN_PAD_PIN_ENTRY_TIMEOUT = 90; // 1 minute, 30 seconds

/** SmartCard manages bidirectional input/output to an ISO 7816 smart card. */
class SmartCard
{
public:
    enum class Protocol { UNDEFINED, T0, T1 }; // AUTO = T0 | T1

    using ptr = std::unique_ptr<SmartCard>;

    class TransactionGuard
    {
    public:
        TransactionGuard(const CardImpl& CardImpl, bool& inProgress);
        ~TransactionGuard();
        PCSC_CPP_DISABLE_COPY_MOVE(TransactionGuard);

    private:
        const CardImpl& card;
        bool& inProgress;
    };

    SmartCard(const ContextPtr& context, const string_t& readerName, byte_vector atr);
    SmartCard(); // Null object constructor.
    ~SmartCard();
    PCSC_CPP_DISABLE_COPY_MOVE(SmartCard);

    TransactionGuard beginTransaction();
    ResponseApdu transmit(const CommandApdu& command) const;
    ResponseApdu transmitCTL(const CommandApdu& command, uint16_t lang, uint8_t minlen) const;
    bool readerHasPinPad() const;

    Protocol protocol() const { return _protocol; }
    const byte_vector& atr() const { return _atr; }

private:
    CardImplPtr card;
    byte_vector _atr;
    Protocol _protocol = Protocol::UNDEFINED;
    bool transactionInProgress = false;
};

/** Reader provides card reader information, status and gives access to the smart card in it. */
class Reader
{
public:
    enum class Status {
        UNAWARE,
        IGNORE,
        CHANGED,
        UNKNOWN,
        UNAVAILABLE,
        EMPTY,
        PRESENT,
        ATRMATCH,
        EXCLUSIVE,
        INUSE,
        MUTE,
        UNPOWERED,
        _
    };

    Reader(ContextPtr context, string_t name, byte_vector cardAtr, flag_set<Status> status);

    SmartCard::ptr connectToCard() const { return std::make_unique<SmartCard>(ctx, name, cardAtr); }

    bool isCardInserted() const { return status[Status::PRESENT]; }

    std::string statusString() const;

    const string_t name;
    const byte_vector cardAtr;
    const flag_set<Status> status;

private:
    ContextPtr ctx;
};

/**
 * Access system smart card readers, entry point to the library.
 *
 * @throw ScardError, SystemError
 */
std::vector<Reader> listReaders();

// Utility functions.

/** Transmit APDU command and verify that expected response is received. */
void transmitApduWithExpectedResponse(const SmartCard& card, const CommandApdu& command);

/** Read data length from currently selected file header, file must be ASN.1-encoded. */
size_t readDataLengthFromAsn1(const SmartCard& card);

/** Read lenght bytes from currently selected binary file in blockLength-sized chunks. */
byte_vector readBinary(const SmartCard& card, const size_t length, byte_type blockLength);

// Errors.

/** Base class for all pcsc-cpp errors. */
class Error : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

/** Programming or system errors. */
class SystemError : public Error
{
public:
    using Error::Error;
};

/** Base class for all SCard API errors. */
class ScardError : public Error
{
public:
    using Error::Error;
};

/** Thrown when the PC/SC service is not running. */
class ScardServiceNotRunningError : public ScardError
{
public:
    using ScardError::ScardError;
};

/** Thrown when no card readers are connected to the system. */
class ScardNoReadersError : public ScardError
{
public:
    using ScardError::ScardError;
};

/** Thrown when no card is connected to the selected reader. */
class ScardNoCardError : public ScardError
{
public:
    using ScardError::ScardError;
};

/** Thrown when communication with the card or reader fails. */
class ScardCardCommunicationFailedError : public ScardError
{
public:
    using ScardError::ScardError;
};

/** Thrown when the card is removed from the selected reader. */
class ScardCardRemovedError : public ScardError
{
public:
    using ScardError::ScardError;
};

/** Thrown when the card transaction fails. */
class ScardTransactionFailedError : public ScardError
{
public:
    using ScardError::ScardError;
};

} // namespace pcsc_cpp
