// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include <string>
#include <set>
#include <map>
#include <vector>
#include <stdexcept>
#include <cstdint>

#ifdef _WIN32
using MOCK_LONG = int32_t;
#else
using MOCK_LONG = uint32_t;
#endif

class PcscMockError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

class PcscMock
{
public:
    using byte_vector = std::vector<unsigned char>;
    // An APDU script is a list of request-response APDU pairs.
    using ApduScript = std::vector<std::pair<byte_vector, byte_vector>>;
    // Define local string type so that we can use wstring in Windows if needed.
#ifdef _WIN32
    using string_t = std::wstring;
#else
    using string_t = std::string;
#endif

    static void callScardFunction(const std::string& function)
    {
        instance()._recordedCalls.insert(function);
    }

    static bool wasScardFunctionCalled(const std::string& scardFunction)
    {
        return instance()._recordedCalls.contains(scardFunction);
    }

    static void addReturnValueForScardFunctionCall(const std::string& scardFunctionName,
                                                   MOCK_LONG returnValue)
    {
        instance()._scardCallReturnValues[scardFunctionName] = returnValue;
    }

    static uint32_t returnValueForScardFunctionCall(const std::string& scardFunctionName)
    {
        // If the key does not exist, then std::map inserts it with a zero-initialized value,
        // this means that default return value is SCARD_S_SUCCESS.
        return instance()._scardCallReturnValues[scardFunctionName];
    }

    static byte_vector responseForApduCommand(const byte_vector& command);

    static void reset()
    {
        auto& self = instance();

        self._recordedCalls.clear();
        self._scardCallReturnValues.clear();
        self._atr = DEFAULT_CARD_ATR;
        self._script = DEFAULT_SCRIPT;
        self._stepCount = 0;
    }

    static void setApduScript(const ApduScript& script)
    {
        auto& self = instance();
        self._script = script;
        self._stepCount = 0;
    }

    static const byte_vector& atr() { return instance()._atr; }
    static void setAtr(const byte_vector& atr) { instance()._atr = atr; }

    static const byte_vector DEFAULT_CARD_ATR;
    static const string_t DEFAULT_READER_NAME;

    static const byte_vector DEFAULT_COMMAND_APDU;
    static const byte_vector DEFAULT_RESPONSE_APDU;
    static const ApduScript DEFAULT_SCRIPT;

private:
    PcscMock() = default;
    ~PcscMock() = default;

    // The rule of five (C++ Core guidelines C.21).
    PcscMock(const PcscMock&) = delete;
    PcscMock& operator=(const PcscMock&) = delete;
    PcscMock(PcscMock&&) = delete;
    PcscMock& operator=(PcscMock&&) = delete;

    static PcscMock& instance()
    {
        static PcscMock self;
        return self;
    }

    std::set<std::string> _recordedCalls;
    std::map<std::string, MOCK_LONG> _scardCallReturnValues;
    byte_vector _atr = DEFAULT_CARD_ATR;
    ApduScript _script = DEFAULT_SCRIPT;
    size_t _stepCount = 0;
};
